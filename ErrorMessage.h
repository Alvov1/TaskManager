#ifndef ERRORMESSAGE_H
#define ERRORMESSAGE_H

#include <QDialog>

namespace Ui {
class ErrorMessage;
}

class ErrorMessage : public QDialog
{
    Q_OBJECT

public:
    explicit ErrorMessage(const std::string& msg, QWidget *parent = nullptr);
    ~ErrorMessage();

private:
    Ui::ErrorMessage *ui;
};

#endif // ERRORMESSAGE_H
