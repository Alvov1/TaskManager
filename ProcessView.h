#ifndef PROCESSVIEW_H
#define PROCESSVIEW_H

#include <QDialog>
#include <QLabel>
#include <QTextEdit>
#include <QListWidget>
#include <fstream>
#include "Process.h"
#include "JsonSaved.h"
#include "ErrorMessage.h"

namespace Ui {
class ProcessView;
unsigned GenerateProcessList(std::list<Process>& list);
}

class ProcessView : public QDialog
{
    Q_OBJECT

    std::list<Process>* listPtr = nullptr;
    std::list<Process>::iterator nowWatching;

public:
    explicit ProcessView(QWidget *parent = nullptr);
    ~ProcessView();

private slots:
    void on_listWidget_itemClicked(QListWidgetItem *item);

    void on_pushButton_2_clicked();

    void on_pushButton_clicked();

private:
    Ui::ProcessView *ui;
};

#endif // PROCESSVIEW_H
