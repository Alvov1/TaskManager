#ifndef FILEEDIT_H
#define FILEEDIT_H

#include <QDialog>

namespace Ui {
class FileEdit;
}

class FileEdit : public QDialog
{
    Q_OBJECT

public:
    explicit FileEdit(QWidget *parent = nullptr);
    ~FileEdit();

private:
    Ui::FileEdit *ui;
};

#endif // FILEEDIT_H
