#ifndef JSONSAVED_H
#define JSONSAVED_H

#include <QDialog>

namespace Ui {
class JsonSaved;
}

class JsonSaved : public QDialog
{
    Q_OBJECT

public:
    explicit JsonSaved(QWidget *parent = nullptr);
    ~JsonSaved();

private:
    Ui::JsonSaved *ui;
};

#endif // JSONSAVED_H
