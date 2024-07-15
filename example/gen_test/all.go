package main

type allField struct {
	BaseArgs
}

func (allField *allField) Attack() (response *HTTPMessage, err error) {
	return nil, nil
}
