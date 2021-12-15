#ifndef FILEVIEW_H
#define FILEVIEW_H

#include <QDialog>
#include <QLabel>
#include <QTextEdit>
#include <QListWidget>
#include <filesystem>
#include "File.h"
#include "ErrorMessage.h"

namespace Ui {
class FileView;
void GenerateFilesList(std::list<File>& list, const std::filesystem::path& path = std::filesystem::current_path());
}

class FileView : public QDialog
{
    Q_OBJECT
    std::list<File>* listPtr;
    std::list<File>::iterator nowWatching;

    std::filesystem::path path_ = std::filesystem::current_path();

public:
    explicit FileView(QWidget *parent = nullptr);
    ~FileView();

private slots:
    void on_listWidget_itemClicked(QListWidgetItem *item);

    void on_pushButton_clicked();

    void on_pushButton_2_clicked();

private:
    Ui::FileView *ui;
};

#endif // FILEVIEW_H
