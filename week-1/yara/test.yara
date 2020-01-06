rule Test
{
    strings:
        $a ="hello"
		$b ="world"

    condition:
        any of them
}