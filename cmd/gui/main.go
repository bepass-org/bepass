package main

import (
	"bepass/config"
	"bepass/server"
	"encoding/json"
	"fmt"
	"io"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
)

func main() {
	myApp := app.New()
	myWindow := myApp.NewWindow("Bepass GUI")
	myWindow.Resize(fyne.NewSize(500, 500))

	ui := createUIComponents(&myWindow)

	content := container.NewVBox(
		ui.profile,
		ui.dohLabel,
		ui.dohInput,
		ui.listenLabel,
		ui.listenInput,
		ui.openFileLabel,
		ui.openFileButton,
		layout.NewSpacer(),
		ui.connectButton,
	)

	myWindow.SetContent(content)
	myWindow.ShowAndRun()
}

type UIComponents struct {
	profile        *widget.RadioGroup
	dohLabel       *widget.Label
	dohInput       *widget.Entry
	listenLabel    *widget.Label
	listenInput    *widget.Entry
	openFileLabel  *widget.Label
	openFileButton *widget.Button
	connectButton  *widget.Button
	isConnected    bool
	coreConfig     *config.Config
}

func createUIComponents(myWindow *fyne.Window) *UIComponents {
	ui := &UIComponents{}
	ui.dohInput = widget.NewEntry()
	ui.dohInput.SetText("https://yarp.lefolgoc.net/dns-query")
	ui.listenInput = widget.NewEntry()
	ui.listenInput.SetText("0.0.0.0:8085")
	ui.connectButton = widget.NewButton("Connect", func() {
		ui.ToggleConnection(myWindow)
	})
	ui.connectButton.Enable()

	ui.dohLabel = widget.NewLabel("DOH Address:")
	ui.listenLabel = widget.NewLabel("Socks Address to listen on:")
	ui.openFileLabel = widget.NewLabel("Config:")

	ui.openFileButton = widget.NewButton("Select", func() {
		fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(err, *myWindow)
				return
			}
			if reader == nil {
				return
			}
			data, err := io.ReadAll(reader)
			if err != nil {
				dialog.ShowError(err, *myWindow)
				return
			}
			err = json.Unmarshal(data, &ui.coreConfig)
			if err != nil {
				dialog.ShowError(err, *myWindow)
				return
			}
			ui.openFileLabel.SetText(fmt.Sprintf("config: %s", reader.URI().String()))
		}, *myWindow)
		cwd, _ := storage.ListerForURI(storage.NewFileURI("."))
		fd.SetLocation(cwd)
		fd.SetFilter(storage.NewExtensionFileFilter([]string{".json"}))
		fd.Show()
	})

	ui.profile = widget.NewRadioGroup([]string{"Default", "Config"}, func(value string) {
		if value == "Default" {
			ui.openFileLabel.Hide()
			ui.openFileButton.Hide()
			ui.dohLabel.Show()
			ui.dohInput.Show()
			ui.listenLabel.Show()
			ui.listenInput.Show()
		} else {
			ui.dohLabel.Hide()
			ui.dohInput.Hide()
			ui.listenLabel.Hide()
			ui.listenInput.Hide()
			ui.openFileLabel.Show()
			ui.openFileButton.Show()
			ui.coreConfig = nil
		}
	})
	ui.profile.SetSelected("Default")

	ui.isConnected = false

	return ui
}

func (ui *UIComponents) ToggleConnection(myWindow *fyne.Window) {
	if ui.isConnected {
		ui.Disconnect(myWindow)
	} else {
		ui.Connect(myWindow)
	}
}

func (ui *UIComponents) Connect(myWindow *fyne.Window) {

	if ui.profile.Selected == "Default" {
		firstValue := ui.dohInput.Text
		secondValue := ui.listenInput.Text

		ui.coreConfig = &config.Config{
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
		}
	}

	if ui.coreConfig == nil {
		dialog.ShowError(fmt.Errorf("config isn't selected"), *myWindow)
		return
	}

	go func() {
		err := server.Run(true)
		if err != nil {
			dialog.ShowError(err, *myWindow)
			ui.isConnected = false
			ui.dohInput.Enable()
			ui.listenInput.Enable()
			ui.connectButton.SetText("Connect")
		}
	}()

	ui.isConnected = true
	ui.dohInput.Disable()
	ui.listenInput.Disable()
	ui.connectButton.SetText("Disconnect")
}

func (ui *UIComponents) Disconnect(myWindow *fyne.Window) {
	go func() {
		if ui.coreConfig != nil {
			err := server.ShutDown()

			if err != nil {
				dialog.ShowError(err, *myWindow)
			}
		}
	}()
	ui.isConnected = false
	ui.dohInput.Enable()
	ui.listenInput.Enable()
	ui.connectButton.SetText("Connect")
}
