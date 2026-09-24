package callbackstore

type Command struct {
	Run func()
}

func (c *Command) Execute() { c.Run() }
