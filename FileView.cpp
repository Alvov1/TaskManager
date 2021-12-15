#include "FileView.h"
#include "ui_FileView.h"

void GenerateFilesList(std::list<File>& list, const std::filesystem::path& path = std::filesystem::current_path()) {
    for(const auto & file : std::filesystem::directory_iterator(path))
        list.emplace_back(file);
}

FileView::FileView(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::FileView)
{
    ui->setupUi(this);

    QFont Font;
    Font.setFamily("Consolas");
    Font.setPixelSize(14);

    ui->label->setFont(Font);
    ui->label->setText("Files in directory");
    ui->label_2->setFont(Font);
    ui->label_2->setText("File information");
    ui->pushButton->setFont(Font);
    ui->pushButton->setText("Change directory");
    ui->pushButton_2->setFont(Font);
    ui->pushButton_2->setText("Edit file");
    ui->listWidget->setFont(Font);
    ui->textEdit->setFont(Font);

    listPtr = new std::list<File>;
    GenerateFilesList(*listPtr);

    for(const auto &file : *listPtr)
        ui->listWidget->addItem(QString::fromStdString(file.Name()));

    nowWatching = listPtr->begin();
    ui->textEdit->setText(QString::fromStdWString(nowWatching->About()));

    connect(ui->listWidget, SIGNAL(itemClicked(QListWidgetItem*)),
            this, SLOT(itemClicked(QListWidgetItem*)));
}

void FileView::on_listWidget_itemClicked(QListWidgetItem *item){
    for(auto iter = listPtr->begin(); iter != listPtr->end(); ++iter)
        if(item->text() == QString::fromStdString(iter->Name())) {
            nowWatching = iter;
            ui->textEdit->setText(QString::fromStdWString(iter->About()));
            return;
        }
}

FileView::~FileView()
{
    delete ui;
}

void FileView::on_pushButton_clicked()
{
    listPtr->clear();
    ui->listWidget->clear();

    while(true) {
        try {
            auto newPath = std::filesystem::path((ui->lineEdit->text()).toStdWString());
            path_ = newPath;
        } catch(...) {
            ui->pushButton->setText("Incorrect path. Try again");
            continue;
        }
        break;
    }
    ui->lineEdit->clear();

    GenerateFilesList(*listPtr, path_);

    for(const auto &file : *listPtr)
        ui->listWidget->addItem(QString::fromStdString(file.Name()));

    ui->textEdit->setText(QString::fromStdWString(listPtr->begin()->About()));
}


void FileView::on_pushButton_2_clicked()
{
    auto input = (ui->lineEdit_2->text()).toStdString();

    if("ACL" == input.substr(0, 3) || "acl" == input.substr(0, 3)) {
        try {
            auto mode = std::stoi(input.substr(4, 5));
            auto permissions = input.substr(5);
            nowWatching->SetACL(permissions, ACCESS_MODE(mode));
        } catch(const std::invalid_argument& e) {
            ErrorMessage msg("Mode should be a number!");
            msg.setModal(true);
            msg.exec();
            return;
        } catch(const std::runtime_error& e) {
            ErrorMessage msg(e.what());
            msg.setModal(true);
            msg.exec();
            return;
        }
        ui->textEdit->setText(QString::fromStdWString(nowWatching->About()));
        std::cout << "ACL changed successfully" << std::endl;
        return;
    };

    if("Integrity" == input.substr(0, 9) || "integrity" == input.substr(0, 9)) {
        try{
            if(input.substr(10, 13) == "Low" || input.substr(10, 13) == "low")
                nowWatching->SetIntegrity(Low);

            if(input.substr(10, 15) == "Medium" || input.substr(10, 15) == "medium")
                nowWatching->SetIntegrity(Medium);

            if(input.substr(10, 14) == "High" || input.substr(10, 14) == "high")
                nowWatching->SetIntegrity(High);
        } catch (const std::runtime_error& e) {
            ErrorMessage msg(e.what());
            msg.setModal(true);
            msg.exec();
            return;
        }
        ui->textEdit->setText(QString::fromStdWString(nowWatching->About()));
        std::cout << "Integrity changed successfully" << std::endl;
        return;
    };

    if("Owner" == input.substr(0, 5) || "owner" == input.substr(0, 5)) {
        try {
            nowWatching->SetOwner(input.substr(6));
        } catch(const std::runtime_error& e) {
            ErrorMessage msg(e.what());
            msg.setModal(true);
            msg.exec();
            return;
        }
        ui->textEdit->setText(QString::fromStdWString(nowWatching->About()));
        std::cout << "Owner changed successfully" << std::endl;
        return;
    };

    ErrorMessage msg("There are 3 commands available:"
                     "\n\tOwner ownerName"
                     "\n\tIntegrity integrityLevel"
                     "\n\tACL mode permissions"
                     "\n\n\tModes for ACL:"
                     "\n\tNOT_USED_ACCESS = 0,"
                     "\n\tGRANT_ACCESS = 1,"
                     "\n\tSET_ACCESS = 2,"
                     "\n\tDENY_ACCESS = 3,"
                     "\n\tREVOKE_ACCESS = 4,"
                     "\n\tSET_AUDIT_SUCCESS = 5,"
                     "\n\tSET_AUDIT_FAILURE = 6");
    msg.setModal(true);
    msg.exec();
}

