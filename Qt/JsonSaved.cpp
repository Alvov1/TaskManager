#include "JsonSaved.h"
#include "ui_JsonSaved.h"

JsonSaved::JsonSaved(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::JsonSaved)
{
    ui->setupUi(this);
    QFont Font;
    Font.setFamily("Consolas");
    Font.setPixelSize(14);

    ui->label->setFont(Font);
    ui->label->setText("Saved to 'output.json' file");
}

JsonSaved::~JsonSaved()
{
    delete ui;
}
