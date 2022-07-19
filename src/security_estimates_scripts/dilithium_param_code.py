
def snippets_polyzpack(bitwidth=19,  N=256, pack=True):
    offset = 8
    bitPosData = 0
    dataIndex = 0
    print("r[%d * i + %d] = t[%d] >> %d;" % (bitwidth, 0, dataIndex, bitPosData))
    for byteIndex in range(1, bitwidth):
        if bitPosData+offset > bitwidth:
            dataIndex += 1
            counterPos = bitwidth-bitPosData
            print("r[%d * i + %d] |= t[%d] << %d;" % (bitwidth, byteIndex-1, dataIndex, counterPos))
            bitPosData = offset - counterPos
            print("r[%d * i + %d] = t[%d] >> %d;" % (bitwidth, byteIndex, dataIndex, bitPosData))
        else:
            bitPosData += offset
            print("r[%d * i + %d] = t[%d] >> %d;" % (bitwidth, byteIndex, dataIndex, bitPosData))

if __name__ == "__main__":
    snippets_polyzpack(21)