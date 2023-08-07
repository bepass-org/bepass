package main

import (
	"bepass/cmd/core"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

func main() {
	myApp := app.New()
	myWindow := myApp.NewWindow("Bepass GUI")
	myWindow.Resize(fyne.NewSize(300, 300))

	ui := createUIComponents()

	content := container.NewVBox(
		widget.NewLabel("DOH Address:"),
		ui.dohInput,
		widget.NewLabel("Socks Address to listen on:"),
		ui.listenInput,
		ui.connectButton,
	)

	myWindow.SetContent(content)
	myWindow.ShowAndRun()
}

type UIComponents struct {
	dohInput      *widget.Entry
	listenInput   *widget.Entry
	connectButton *widget.Button
	isConnected   bool
	coreConfig    *core.Config
}

func createUIComponents() *UIComponents {
	ui := &UIComponents{}
	ui.dohInput = widget.NewEntry()
	ui.dohInput.SetText("https://yarp.lefolgoc.net/dns-query")
	ui.listenInput = widget.NewEntry()
	ui.listenInput.SetText("0.0.0.0:8085")
	ui.connectButton = widget.NewButton("Connect", func() {
		ui.ToggleConnection()
	})
	ui.connectButton.Enable()

	ui.isConnected = false

	return ui
}

func (ui *UIComponents) ToggleConnection() {
	if ui.isConnected {
		ui.Disconnect()
	} else {
		ui.Connect()
	}
}

func (ui *UIComponents) Connect() {
	firstValue := ui.dohInput.Text
	secondValue := ui.listenInput.Text

	config := &core.Config{
		TLSHeaderLength:       5,
		DnsCacheTTL:           3600,
		WorkerAddress:         "worker.example.com",
		WorkerIPPortAddress:   "192.168.0.1:8080",
		WorkerEnabled:         true,
		WorkerDNSOnly:         false,
		RemoteDNSAddr:         firstValue,
		BindAddress:           secondValue,
		ChunksLengthBeforeSni: [2]int{10, 20},
		SniChunksLength:       [2]int{30, 40},
		ChunksLengthAfterSni:  [2]int{50, 60},
		DelayBetweenChunks:    [2]int{70, 80},
		ResolveSystem:         "doh",
		DoHClient:             nil, // Initialize appropriately
	}

	ui.coreConfig = config

	go func() {
		err := core.RunServer(config, true)
		if err != nil {
			//errorMessage := "Error: " + err.Error()
			// Later we can handle the error using a dialog
		}
	}()

	ui.isConnected = true
	ui.dohInput.Disable()
	ui.listenInput.Disable()
	ui.connectButton.SetText("Disconnect")
}

func (ui *UIComponents) Disconnect() {
	go func() {
		if ui.coreConfig != nil {
			err := core.ShutDown()

			if err != nil {
				// Later we can handle the error using a dialog
			}
		}
	}()
	ui.isConnected = false
	ui.dohInput.Enable()
	ui.listenInput.Enable()
	ui.connectButton.SetText("Connect")
}
