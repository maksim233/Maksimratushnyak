#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "class.h"
#include <algorithm>

using namespace std;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    connect(ui->Start,SIGNAL(clicked()),SLOT(Start()));
    connect(ui->Sort,SIGNAL(clicked()),SLOT(Sort()));
    mSize_ip = sizeof(struct sniff_ip);

}

MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::Start()
{
    mPacket.resize(n);
    for (int i=0; i<n; i++)
    {
        mPacket[i].mHeaders.clear();
        mPacket[i].mDatas.clear();
        mPacket[i].mIp.clear();
        mPacket[i].mIndexes.clear();
    }

    ui->Text->clear();

    char error[PCAP_ERRBUF_SIZE];
    char file[127];

    strcpy(file,ui->Pcap->text().toStdString().c_str());
    pcap_t *handle = pcap_open_offline(file, error);

    ui->Text->append("Список пакетов:");

    for (int i=0; i<n; i++)
    {
        struct pcap_pkthdr *header;
        const u_char *data;

        pcap_next_ex(handle,&header,&data);

        mPacket[i].mHeaders.push_back(new pcap_pkthdr);
        *mPacket[i].mHeaders[0] =* header;
        mPacket[i].mDatas.push_back(new u_char[mPacket[i].mHeaders[0]->len]);
        for (unsigned j = 0; j < mPacket[i].mHeaders[0]->len; j++)
            mPacket[i].mDatas[0][j] = data[j];
        mPacket[i].mIp.push_back((struct sniff_ip*)(mPacket[i].mDatas[0]));
        mPacket[i].mIndexes.push_back(i+1);

        ui->Text->append(QString("\nПакет №%1").arg(mPacket[i].mIndexes[0]));
        ui->Text->append(QString("Длина пакета: %1").arg(header->caplen));
        ui->Text->append(QString("Получено: %1").arg(header->len));
        ui->Text->append(QString("Метка времени: %1").arg(header->ts.tv_sec));
    }

    pcap_close(handle);
}

void MainWindow::Sort()
{
    ui->Text->clear();
    if (ui->Type1->currentText() == "Внутренняя")
    {
        if (ui->Type2->currentText() == "По длине пакета")
        {
            int h, i, j;
            for (h = n/2; h > 0; h = h/2)
                for(i = 0; i < n-h; i++)
                    for(j = i; j >= 0; j = j - h)
                        if(mPacket[j].mIp[0]->ip_len > mPacket[j+h].mIp[0]->ip_len)
                            Chage(j, j+h);
                        else j = 0;
        }
        else if (ui->Type2->currentText() == "По времени жизни")
        {
            int h, i, j;
            for (h = n/2; h > 0; h = h/2)
                for(i = 0; i < n-h; i++)
                    for(j = i; j >= 0; j = j - h)
                        if(mPacket[j].mIp[0]->ip_ttl > mPacket[j+h].mIp[0]->ip_ttl)
                            Chage(j, j+h);
                        else j = 0;
        }
        else if (ui->Type2->currentText() == "По адресу получателя")
        {
            int h, i, j;
            for (h = n/2; h > 0; h = h/2)
                for(i = 0; i < n-h; i++)
                    for(j = i; j >= 0; j = j - h)
                        if(mPacket[j].mIp[0]->ip_dst.s_addr > mPacket[j+h].mIp[0]->ip_dst.s_addr)
                            Chage(j, j+h);
                        else j = 0;
        }
        else if (ui->Type2->currentText() == "По адресу отправителя")
        {
            int h, i, j;
            for (h = n/2; h > 0; h = h/2)
                for(i = 0; i < n-h; i++)
                    for(j = i; j >= 0; j = j - h)
                        if(mPacket[j].mIp[0]->ip_src.s_addr > mPacket[j+h].mIp[0]->ip_src.s_addr)
                            Chage(j, j+h);
                        else j = 0;
        }
        else if (ui->Type2->currentText() == "По длине заголовочной части пакета")
        {
            int h, i, j;
            for (h = n/2; h > 0; h = h/2)
                for(i = 0; i < n-h; i++)
                    for(j = i; j >= 0; j = j - h)
                        if(mPacket[j].mIp[0]->ip_vhl > mPacket[j+h].mIp[0]->ip_vhl)
                            Chage(j, j+h);
                        else j = 0;
        }
        else if (ui->Type2->currentText() == "По контрольной сумме (первый байт контрольной суммы)")
        {
            int h, i, j;
            for (h = n/2; h > 0; h = h/2)
                for(i = 0; i < n-h; i++)
                    for(j = i; j >= 0; j = j - h)
                        if((mPacket[j].mIp[0]->ip_sum & 0xFF00) > (mPacket[j+h].mIp[0]->ip_sum & 0xFF00))
                             Chage(j, j+h);
                        else j = 0;
        }
        else if (ui->Type2->currentText() == "По контрольной сумме (последний байт контрольной суммы)")
        {
            int h, i, j;
            for (h = n/2; h > 0; h = h/2)
                for(i = 0; i < n-h; i++)
                    for(j = i; j >= 0; j = j - h)
                        if((mPacket[j].mIp[0]->ip_sum & 0xFF) > (mPacket[j+h].mIp[0]->ip_sum & 0xFF))
                             Chage(j, j+h);
                        else j = 0;
        }
        for (int i=0; i<n; i++)
        {
            ui->Text->append(QString("----- Пакет №%1 -----").arg(mPacket[i].mIndexes[0]));
            ui->Text->append(QString("Длина пакета: %1").arg(mPacket[i].mHeaders[0]->caplen));
            ui->Text->append(QString("Получено: %1").arg(mPacket[i].mHeaders[0]->len));
            ui->Text->append(QString("Метка времени: %1").arg(mPacket[i].mHeaders[0]->ts.tv_sec));

            ui->Text->append(QString("---------- IP сортировка: ----------"));
            ui->Text->append(QString("Длина: %1").arg(mPacket[i].mIp[0]->ip_len));
            ui->Text->append(QString("Время жизни: %1").arg(mPacket[i].mIp[0]->ip_ttl));
            ui->Text->append(QString("Адрес получателя: %1").arg(mPacket[i].mIp[0]->ip_dst.s_addr));
            ui->Text->append(QString("Адрес отправителя: %1").arg(mPacket[i].mIp[0]->ip_src.s_addr));
            ui->Text->append(QString("Длина заголовочной части пакета: %1").arg(mPacket[i].mIp[0]->ip_vhl));
            ui->Text->append(QString("Контрольная сумма: %1").arg(mPacket[i].mIp[0]->ip_sum));
            ui->Text->append(QString("Тип обслуживания: %1").arg(mPacket[i].mIp[0]->ip_tos));
            ui->Text->append(QString("\n========================================\n"));
        }
    }


}

void MainWindow::Chage(int i, int j)
{
    std::swap(mPacket[i].mHeaders[0], mPacket[j].mHeaders[0]);
    std::swap(mPacket[i].mDatas[0], mPacket[j].mDatas[0]);
    std::swap(mPacket[i].mIp[0], mPacket[j].mIp[0]);
    std::swap(mPacket[i].mIndexes[0], mPacket[j].mIndexes[0]);
}

bool operator < (Packet &obj1, Packet &obj2)
{
    switch (Packet::choose)
    {
    case 1:
        if (obj1.mHeaders[0]->len < obj2.mHeaders[0]->len) return true;
        else return false;
        break;
    }
}

bool operator < (const Packet &obj1, Packet &obj2)
{
    switch (Packet::choose)
    {
    case 1:
        if (obj1.mHeaders[0]->len < obj2.mHeaders[0]->len) return true;
        else return false;
        break;
    }
}

bool operator < (Packet &obj1, const Packet &obj2)
{
    switch (Packet::choose)
    {
    case 1:
        if (obj1.mHeaders[0]->len < obj2.mHeaders[0]->len) return true;
        else return false;
        break;
    }
}

bool operator < (const Packet &obj1, const Packet &obj2)
{
    switch (Packet::choose)
    {
    case 1:
        if (obj1.mHeaders[0]->len < obj2.mHeaders[0]->len) return true;
        else return false;
        break;
    }
}
