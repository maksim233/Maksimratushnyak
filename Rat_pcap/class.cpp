#include "class.h"

Packet::Packet()
{};

Packet::Packet(const Packet &obj) // описание конструктора копирования
{
    mHeaders[0] = obj.mHeaders[0];
    mDatas[0] = obj.mDatas[0];
    mIp[0] = obj.mIp[0];
    mIndexes[0] = obj.mIndexes[0];
}

Packet Packet::operator = (Packet &obj) // описание оператора присваивания
{
    this->mHeaders[0] = obj.mHeaders[0];
    this->mDatas[0] = obj.mDatas[0];
    this->mIp[0] = obj.mIp[0];
    this->mIndexes[0] = obj.mIndexes[0];
    
    return *this;
}

Packet Packet::operator = (const Packet &obj) // описание оператора присваивания
{
    this->mHeaders[0] = obj.mHeaders[0];
    this->mDatas[0] = obj.mDatas[0];
    this->mIp[0] = obj.mIp[0];
    this->mIndexes[0] = obj.mIndexes[0];

    return *this;
}

int Packet::choose;
