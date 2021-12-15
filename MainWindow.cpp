#include "MainWindow.h"
#include "./ui_MainWindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    QFont Font;
    Font.setFamily("Consolas");
    Font.setPixelSize(14);

    ui->pushButton->setFont(Font);
    ui->pushButton->setText("Files in directory");

    ui->pushButton_2->setFont(Font);
    ui->pushButton_2->setText("Running processes");
}

MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::on_pushButton_2_clicked()
{
    ProcessView dialog;
    dialog.setModal(true);
    dialog.exec();
}


void MainWindow::on_pushButton_clicked()
{
    FileView dialog;
    dialog.setModal(true);
    dialog.exec();
}

