#include "ErrorMessage.h"
#include "ui_ErrorMessage.h"

ErrorMessage::ErrorMessage(const std::string& msg, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ErrorMessage)
{
    ui->setupUi(this);

    QFont Font;
    Font.setFamily("Consolas");
    Font.setPixelSize(14);

    ui->label->setFont(Font);
    ui->label->setText(QString::fromStdString(msg));
}

/* "There are 2 commands available:"
                           "\n\tIntegrity integrityLevel"
                           "\n\tPrivilege privilege" */

ErrorMessage::~ErrorMessage()
{
    delete ui;
}
