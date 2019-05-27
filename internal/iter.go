package internal

// Chain makes an iterator that returns elements from the first iterable until it is exhausted,
//then proceeds to the next iterable, until all of the iterables are exhausted.
// Used for treating consecutive sequences as a single sequence
func Chain(iterables ...[]string) <-chan string {
	chnl := make(chan string)
	go func() {
		for _, iterable := range iterables {
			for _, element := range iterable {
				chnl <- element
			}
		}

		// Ensure that at the end of the loop we close the channel!
		close(chnl)
	}()
	return chnl
}
