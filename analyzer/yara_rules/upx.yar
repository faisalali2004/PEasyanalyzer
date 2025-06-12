rule UPX_Packed {
    meta:
        description = "Detects UPX packed files"
    strings:
        $upx1 = "UPX0"
        $upx2 = "UPX1"
    condition:
        $upx1 or $upx2
}