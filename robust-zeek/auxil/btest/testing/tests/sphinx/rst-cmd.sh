# %TEST-EXEC: bash %INPUT

%TEST-START-FILE file.txt
Example file.
Line 2
%TEST-END-FILE

unset TEST_NAME
btest-rst-cmd echo Hello >>output
btest-rst-cmd -o echo "Hello 2, no command" >>output
btest-rst-cmd -c "Different command" echo "Hello 3, no command" >>output
btest-rst-cmd -d echo "Hello 4, no output" >>output
btest-rst-cmd -f 'tr e X' echo "Hello 5, filter" >>output
btest-rst-cmd -r file.txt echo "Hello 6, file" >>output
btest-diff output

