set args -f -vvvv
set detach-on-fork on
set follow-fork-mode child

define str_vector_dump
	set $i = $arg1
	while $i < $arg2
		print (const char *) ((struct iovec *) $arg0)[$i].iov_base
		set $i = $i + 1
	end
end

document str_vector_dump
Print the string elements of struct iovec.

	Usage: str_vector_dump <vector> <start_index> <end_index>
end
