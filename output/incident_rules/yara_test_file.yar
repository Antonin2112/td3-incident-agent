rule test_yara_simple : "test_yara_simple" {
    strings:
        $a = "Write"
        $b = "Host"
    condition:
        $a and $b
}