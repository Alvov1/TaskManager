#include "ProcessView.h"
#include "ui_ProcessView.h"

unsigned GenerateProcessList(std::list<Process>& list) {
    list.clear();

    auto* pEntry = new PROCESSENTRY32;
    pEntry->dwSize = sizeof(*pEntry);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if(snap != INVALID_HANDLE_VALUE) {
        for(auto i = Process32First(snap, pEntry); i; i = Process32Next(snap, pEntry))
            list.push_back(Process(pEntry->th32ProcessID, pEntry->th32ParentProcessID, pEntry->szExeFile));

        CloseHandle(snap);
        delete pEntry;
        return 0;
    }

    delete pEntry;
    return 1;
}

ProcessView::ProcessView(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ProcessView)
{
    ui->setupUi(this);
    QFont Font;
    Font.setFamily("Consolas");
    Font.setPixelSize(14);

    /* Appearance settings. */
    ui->label->setText("Running processes");
    ui->label->setFont(Font);
    ui->label_2->setText("Process info");
    ui->label_2->setFont(Font);
    ui->pushButton->setFont(Font);
    ui->pushButton->setText("Edit process");
    ui->pushButton_2->setFont(Font);
    ui->pushButton_2->setText("Save to .json");
    ui->listWidget->setFont(Font);
    ui->listWidget->setItemAlignment(Qt::AlignLeft);
    ui->textEdit->setFont(Font);

    /* Actual backend. */
    listPtr = new std::list<Process>;
    GenerateProcessList(*listPtr);

    /* It the beginning, listening info about the first process on the list. */
    ui->textEdit->setText(QString::fromStdWString(listPtr->begin()->About()));
    nowWatching = listPtr->begin();

    /* Filling up listWidget. */
    for(auto &proc : *listPtr)
        ui->listWidget->addItem(QString::fromStdWString(proc.Name()));

    connect(ui->listWidget, SIGNAL(itemClicked(QListWidgetItem*)),
            this, SLOT(itemClicked(QListWidgetItem*)));

}

void ProcessView::on_listWidget_itemClicked(QListWidgetItem *item)
{
    for(auto iter = listPtr->begin(); iter != listPtr->end(); ++iter)
        if(item->text() == QString::fromStdWString(iter->Name())) {
            nowWatching = iter;
            ui->textEdit->setText(QString::fromStdWString(iter->About()));
            return;
        }
}

ProcessView::~ProcessView()
{
    delete ui;
}


void ProcessView::on_pushButton_2_clicked()
{
    std::wofstream file("output.json");
    for(auto &proc : *listPtr)
        file << proc.jsonAbout() << std::endl;

    file.close();

    JsonSaved output;
    output.setModal(true);
    output.exec();
}


void ProcessView::on_pushButton_clicked()
{
    auto input = (ui->lineEdit->text()).toStdString();

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

    if("Privilege" == input.substr(0, 9) || "privilege" == input.substr(0, 9)) {
        try{
            std::string priv = input.substr(10, input.find(' ', 10));
            std::string mode = input.substr(input.find(' ', 10));
            if(mode == "on" || mode == "ON")
                nowWatching->SetPrivileges(priv, true);
            else
                nowWatching->SetPrivileges(priv, false);

        } catch (const std::runtime_error& e) {
            ErrorMessage msg(e.what());
            msg.setModal(true);
            msg.exec();
            return;
        }
        ui->textEdit->setText(QString::fromStdWString(nowWatching->About()));
        std::cout << "Privilege changed successfully" << std::endl;
    }

    ErrorMessage msg("There are 2 commands available:"
                     "\n\tIntegrity integrityLevel"
                     "\n\tPrivilege privilege mode"
                     "\n\n\tPrivilege modes: on/off");
    msg.setModal(true);
    msg.exec();
}

