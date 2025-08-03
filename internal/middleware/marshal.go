package middleware

import (
	"encoding/json"
	"fmt"
	"github.com/gofiber/fiber/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

/*
MarshalProtobuf - Marshal's and sends a protobuf while populating any errors that occur during the process. This
function is required as by default protobuf emits empty fields
*/
func MarshalProtobuf(c fiber.Ctx, message proto.Message) error {
	marshaler := protojson.MarshalOptions{
		EmitUnpopulated: true,
		UseProtoNames:   true,
	}

	data, err := marshaler.Marshal(message)
	if err != nil {
		wrappedErr := fmt.Errorf("%w (%v)", ErrFailedToBindResponse, err)
		return HandleError(c, wrappedErr)
	}

	c.Set("Content-Type", "application/json; charset=utf-8")
	return c.Status(200).Send(data)
}

/*
MarshalProtobufList - Marshal's a list of protocol buffers and returns them as a response. Content-Type will automatically
be set to 'application/json' and the status code to 200.

This really is a non-ideal way of handling this as we need to iterate through the entire slice here, potentially wasting
some CPU time.
*/
func MarshalProtobufList[T proto.Message](c fiber.Ctx, message []T) error {
	marshaler := protojson.MarshalOptions{
		EmitUnpopulated: true,
		UseProtoNames:   true,
	}

	/*
		We only want to allocate enough memory here for our freshly marshaled structures, so instead of creating a slice
		directly with: 'var ret []byte', we use make to allocate a slice with length 0, and a capacity that supports the
		size of our 'message' param.

		This is ugly tbh. A slice of byte slices is not ideal, but it works :)
	*/
	ret := make([]json.RawMessage, 0, len(message))

	/*
		Since the 'message' slice will contain potentially large structs, we don't want to use the range keyword as this
		requires an additional copy into the variable we declare in the loop. Instead, we directly access the data stored
		with an index in a traditional C style array
	*/
	for i := 0; i < len(message); i++ {
		data, err := marshaler.Marshal(message[i])
		if err != nil {
			wrappedErr := fmt.Errorf("%w (%v)", ErrFailedToBindResponse, err)
			return HandleError(c, wrappedErr)
		}

		ret = append(ret, data)
	}

	c.Set("Content-Type", "application/json; charset=utf-8")

	return c.Status(200).JSON(ret)
}

/*
BindJSON - Bind's a response to a protobuf message and wraps any errors that occur with ErrFailedToBindResponse
*/
func BindJSON(c fiber.Ctx, message proto.Message) error {
	err := c.Bind().JSON(message)
	if err != nil {
		wrappedErr := fmt.Errorf("%w (%v)", ErrFailedToBindResponse, err)
		return HandleError(c, wrappedErr)
	}

	return nil
}
