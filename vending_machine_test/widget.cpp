#include "widget.h"
#include "ui_widget.h"

Widget::Widget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Widget)
{
    ui->setupUi(this);
    enableCheck();
}

Widget::~Widget()
{
    delete ui;
}

void Widget::changeMoney(int n)
{

    money += n;
    enableCheck();
    ui->lcdNumber->display(money);
}

void Widget::enableCheck()
{

    if(money <0)
    {
        money=0;
    }

    if(money<100)
    {
        ui->pbCoffee->setEnabled(false);
        ui->pbTea->setEnabled(false);
        ui->pbJuice->setEnabled(false);
    }
    else if(100<=money && 150>money)
    {
        ui->pbCoffee->setEnabled(true);
        ui->pbJuice->setEnabled(false);
        ui->pbTea->setEnabled(false);

    }
    else if(150<=money && 200>money)
    {
        ui->pbCoffee->setEnabled(true);
        ui->pbJuice->setEnabled(false);
        ui->pbTea->setEnabled(true);

    }
    else
    {
        ui->pbCoffee->setEnabled(true);
        ui->pbJuice->setEnabled(true);
        ui->pbTea->setEnabled(true);
    }

}

void Widget::resMoney()
{
    int change[4] = {0};
    int coin[4] = {500, 100, 50, 10};

    for(int i=0; i<4; i++)
    {
        change[i] = money / coin[i];
        money = money % coin[i];
    }

    QString str;
    str = QString("500: %1 \n 100: %2 \n 50: %3 \n 10: %4").arg(change[0]).arg(change[1]).arg(change[2]).arg(change[3]);
    QMessageBox msg;
    msg.information(nullptr, "return", str);

    money = 0;
    enableCheck();
    ui->lcdNumber->display(money);
}

void Widget::on_pb10_clicked()
{
    changeMoney(10);
}

void Widget::on_pb50_clicked()
{
    changeMoney(50);
}

void Widget::on_pb100_clicked()
{
    changeMoney(100);
}

void Widget::on_pb500_clicked()
{
    changeMoney(500);
}

void Widget::on_pbCoffee_clicked()
{
    changeMoney(-100);
}

void Widget::on_pbTea_clicked()
{
    changeMoney(-150);
}

void Widget::on_pbJuice_clicked()
{
    changeMoney(-200);
}

void Widget::on_pbReturn_clicked()
{
    resMoney();
}
