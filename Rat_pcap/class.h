#ifndef CLASS_H
#define CLASS_H
#pragma once

#endif // CLASS_H

#include <QVector>

class Packet
{
public: // инициализвция класса
    static int choose;

    Packet(); // конструктор
    Packet(const Packet &obj); // конструктор копирования

    QVector <struct pcap_pkthdr *> mHeaders;
    QVector <uchar *> mDatas;
    QVector <const struct sniff_ethernet *> mEthernet;
    QVector <const struct sniff_ip *> mIp;
    QVector <const struct sniff_tcp *> mTcp;
    QVector <const uchar *> mPayload;
    QVector <int> mIndexes;

    Packet operator = (Packet &obj); // оперотор присваивание
    Packet operator = (const Packet &obj); // оперотор присваивание

    friend bool operator < (Packet &obj1, Packet &obj2); // операторы сравнения
    friend bool operator < (const Packet &obj1, Packet &obj2);
    friend bool operator < (Packet &obj1, const Packet &obj2);
    friend bool operator < (const Packet &obj1, const Packet &obj2);
};
