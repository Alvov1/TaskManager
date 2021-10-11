#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include <QTableWidget>
#include <QString>

MainWindow::MainWindow(std::list<Process>& list, QWidget *parent)
    : QMainWindow(parent), ProcessCount(static_cast<unsigned>(list.size()))
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->tableWidget->setRowCount(ProcessCount);
    ui->tableWidget->setColumnCount(13);
    ui->tableWidget->setHorizontalHeaderLabels(
                QStringList()
                << "Name"
                << "PID"
                << "Descriptor"
                << "Path"
                << "Parent Name"
                << "PID"
                << "Owner's name"
                << "SID"
                << "Process Type"
                << "Environment"
                << "DEP | ASLR"
                << "Dll list"
                << "Informaiton");

    auto listIter = list.begin();
    for(auto i = 0; i < ui->tableWidget->rowCount(); ++i, ++listIter){
        ui->tableWidget->setItem(i, 0, new QTableWidgetItem(QString::fromStdWString(listIter->Name())));
        ui->tableWidget->setItem(i, 1, new QTableWidgetItem(QString::number(listIter->PID())));
        ui->tableWidget->setItem(i, 2, new QTableWidgetItem(QString::fromStdString("Descriptor")));
        ui->tableWidget->setItem(i, 3, new QTableWidgetItem(QString::fromStdWString(listIter->Path())));
        ui->tableWidget->setItem(i, 4, new QTableWidgetItem(QString::fromStdWString(listIter->ParentName())));
        ui->tableWidget->setItem(i, 5, new QTableWidgetItem(QString::number(listIter->ParentPID())));
        ui->tableWidget->setItem(i, 6, new QTableWidgetItem(QString::fromStdWString(listIter->OwnerName())));
        ui->tableWidget->setItem(i, 7, new QTableWidgetItem(QString::fromStdWString(listIter->SID())));
        ui->tableWidget->setItem(i, 8, new QTableWidgetItem(QString::fromStdString(
                                                                listIter->pType() == x32 ? std::string("x32") : std::string("x64"))));
        ui->tableWidget->setItem(i, 9, new QTableWidgetItem(QString::fromStdString("Environment")));
        ui->tableWidget->setItem(i, 10, new QTableWidgetItem(QString::fromStdString(
                                                                 (listIter->isDEP() ? std::string("True ") : std::string("False "))
                                                                 + std::string("| ")
                                                                 + (listIter->isASLR() ? std::string("True") : std::string("False")))));
        ui->tableWidget->setItem(i, 11, new QTableWidgetItem(QString::fromStdString("Information")));
    }
}

MainWindow::~MainWindow()
{
    delete ui;
}

