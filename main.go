package main

import (
	"crypto/md5"
	"embed"
	"flag"
	"fmt"
	"github.com/atotto/clipboard"
	"github.com/denisbrodbeck/machineid"
	"howett.net/plist"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/unknwon/i18n"
)

var version = 227

var hosts = []string{"http://129.154.205.7:7191", "https://idea.jeter.eu.org", "http://jetbra.serv00.net:7191", "http://ba.serv00.net:7191"}
var host = hosts[1]
var githubPath = "https://ghp.ci/https://github.com/kingparks/jetbra-activate/releases/download/latest/"
var err error

var green = "\033[32m%s\033[0m\n"
var yellow = "\033[33m%s\033[0m\n"
var hGreen = "\033[1;32m%s\033[0m"
var dGreen = "\033[4;32m%s\033[0m\n"
var red = "\033[31m%s\033[0m\n"
var defaultColor = "%s"
var lang, _ = getLocale()
var deviceID = getMacMD5_241018()
var machineID = getMacMD5_241019()

//go:embed all:script
var scriptFS embed.FS

//go:embed all:locales
var localeFS embed.FS

type Tr struct {
	i18n.Locale
}

var tr *Tr

func main() {
	language := flag.String("l", lang, "set language, eg: zh, en, nl, ru, hu, tr")
	flag.Parse()

	localeFileEn, _ := localeFS.ReadFile("locales/en.ini")
	_ = i18n.SetMessage("en", localeFileEn)
	localeFileNl, _ := localeFS.ReadFile("locales/nl.ini")
	_ = i18n.SetMessage("nl", localeFileNl)
	localeFileRu, _ := localeFS.ReadFile("locales/ru.ini")
	_ = i18n.SetMessage("ru", localeFileRu)
	localeFileHu, _ := localeFS.ReadFile("locales/hu.ini")
	_ = i18n.SetMessage("hu", localeFileHu)
	localeFileTr, _ := localeFS.ReadFile("locales/tr.ini")
	_ = i18n.SetMessage("tr", localeFileTr)
	localeFileEs, _ := localeFS.ReadFile("locales/es.ini")
	_ = i18n.SetMessage("es", localeFileEs)
	lang = *language
	switch lang {
	case "zh":
		tr = &Tr{Locale: i18n.Locale{Lang: "zh"}}
	case "nl":
		tr = &Tr{Locale: i18n.Locale{Lang: "nl"}}
	case "ru":
		tr = &Tr{Locale: i18n.Locale{Lang: "ru"}}
	case "hu":
		tr = &Tr{Locale: i18n.Locale{Lang: "hu"}}
	case "tr":
		tr = &Tr{Locale: i18n.Locale{Lang: "tr"}}
	case "es":
		tr = &Tr{Locale: i18n.Locale{Lang: "es"}}
	default:
		tr = &Tr{Locale: i18n.Locale{Lang: "en"}}
	}

	fmt.Printf(green, tr.Tr("IntelliJ 授权")+` v`+strings.Join(strings.Split(fmt.Sprint(version), ""), "."))
	fmt.Println()

	fmt.Printf(defaultColor, tr.Tr("选择要授权的产品："))
	jbProduct := []string{"IntelliJ IDEA", "CLion", "PhpStorm", "Goland", "PyCharm", "WebStorm", "Rider", "DataGrip", "DataSpell"}
	jbProductChoice := []string{"idea", "clion", "phpstorm", "goland", "pycharm", "webstorm", "rider", "datagrip", "dataspell"}
	for i, v := range jbProduct {
		fmt.Printf(hGreen, fmt.Sprintf("%d. %s\t", i+1, v))
	}
	fmt.Println()
	fmt.Print(tr.Tr("请输入产品编号（直接回车默认为1）："))
	productIndex := 1
	_, _ = fmt.Scanln(&productIndex)
	if productIndex < 1 || productIndex > len(jbProduct) {
		fmt.Println(tr.Tr("输入有误"))
		return
	}
	fmt.Println(tr.Tr("选择的产品为：") + jbProduct[productIndex-1])
	fmt.Println()

	for i := 0; i < 50; i++ {
		if i == 20 {
			Clean()
			Active(jbProductChoice[productIndex-1])
		}
		time.Sleep(20 * time.Millisecond)
		h := strings.Repeat("=", i) + strings.Repeat(" ", 49-i)
		fmt.Printf("\r%.0f%%[%s]", float64(i)/49*100, h)
	}
	fmt.Println()
	fmt.Println()

	licenseName := GetLicenseName()
	expireDate := "2099-09-14"

	lic, err := cryptoUtil.GenActivateCode(licenseName, expireDate, JetProducts[productIndex-1])
	if err != nil {
		fmt.Println(tr.Tr("签名工具生成激活码失败"))
		return
	}

	isCopyText := ""
	err = clipboard.WriteAll(lic)
	if err == nil {
		isCopyText = tr.Tr("（已复制到剪贴板）")
	}
	fmt.Printf(yellow, tr.Tr("首次执行请重启IDE，然后填入下面授权码；非首次执行直接填入下面授权码即可")+isCopyText)
	switch runtime.GOOS {
	case "windows":
		_ = exec.Command("taskkill", "/IM", jbProductChoice[productIndex-1]+".exe", "/F").Run()
		_ = exec.Command("taskkill", "/IM", jbProductChoice[productIndex-1]+"64.exe", "/F").Run()
	case "darwin":
		_ = exec.Command("killall", "-9", jbProductChoice[productIndex-1]).Run()
	case "linux":
		_ = exec.Command("killall", "-9", jbProductChoice[productIndex-1]+".sh").Run()
		_ = exec.Command("killall", "-9", "java").Run()
	}
	fmt.Println()
	fmt.Printf(hGreen, lic)
	fmt.Println()
	for i := 0; i < 1; i++ {
		_, _ = fmt.Scanln()
	}
}

func getMacMD5() string {
	// 获取本机的MAC地址
	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("err:", err)
		return ""
	}
	var macAddress []string
	var wifiAddress []string
	var bluetoothAddress []string
	var macErrorStr string
	for _, inter := range interfaces {
		// 排除虚拟网卡
		hardwareAddr := inter.HardwareAddr.String()
		if hardwareAddr == "" {
			//fmt.Println(fmt.Sprintf("log: have not hardwareAddr :%+v",inter))
			continue
		}
		macErrorStr += inter.Name + ":" + hardwareAddr + "\n"
		virtualMacPrefixes := []string{
			"00:05:69", "00:0C:29", "00:1C:14", "00:50:56", // VMware
			"00:15:5D",             // Hyper-V
			"08:00:27", "0A:00:27", // VirtualBox
		}
		isVirtual := false
		for _, prefix := range virtualMacPrefixes {
			if strings.HasPrefix(hardwareAddr, strings.ToLower(prefix)) {
				isVirtual = true
				break
			}
		}
		if isVirtual {
			//fmt.Println(fmt.Sprintf("log: isVirtual :%+v",inter))
			continue
		}
		// 大于en6的排除
		if strings.HasPrefix(inter.Name, "en") {
			numStr := inter.Name[2:]
			num, _ := strconv.Atoi(numStr)
			if num > 6 {
				//fmt.Println(fmt.Sprintf("log: is num>6 :%+v",inter))
				continue
			}
		}
		if strings.HasPrefix(inter.Name, "en") || strings.HasPrefix(inter.Name, "Ethernet") || strings.HasPrefix(inter.Name, "以太网") || strings.HasPrefix(inter.Name, "WLAN") {
			//fmt.Println(fmt.Sprintf("log: add :%+v",inter))
			macAddress = append(macAddress, hardwareAddr)
		} else if strings.HasPrefix(inter.Name, "Wi-Fi") || strings.HasPrefix(inter.Name, "无线网络") {
			wifiAddress = append(wifiAddress, hardwareAddr)
		} else if strings.HasPrefix(inter.Name, "Bluetooth") || strings.HasPrefix(inter.Name, "蓝牙网络连接") {
			bluetoothAddress = append(bluetoothAddress, hardwareAddr)
		} else {
			//fmt.Println(fmt.Sprintf("log: not add :%+v",inter))
		}
	}
	if len(macAddress) == 0 {
		macAddress = append(macAddress, wifiAddress...)
		if len(macAddress) == 0 {
			macAddress = append(macAddress, bluetoothAddress...)
		}
		if len(macAddress) == 0 {
			fmt.Printf(red, "no mac address found,Please contact customer service")
			_, _ = fmt.Scanln()
			return macErrorStr
		}
	}
	sort.Strings(macAddress)
	return fmt.Sprintf("%x", md5.Sum([]byte(strings.Join(macAddress, ","))))
}

func getMac_241018() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("err:", err)
		return ""
	}

	var macError []string
	for _, inter := range interfaces {
		hardwareAddr := inter.HardwareAddr.String()
		if hardwareAddr == "" {
			continue
		}
		macError = append(macError, inter.Name+": "+hardwareAddr)
	}
	sort.Strings(macError)
	return strings.Join(macError, "\n")
}
func getMacMD5_241018() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("err:", err)
		return ""
	}

	var macAddress, bluetoothAddress []string
	virtualMacPrefixes := []string{
		"00:05:69", "00:0C:29", "00:1C:14", "00:50:56", // VMware
		"00:15:5D",             // Hyper-V
		"08:00:27", "0A:00:27", // VirtualBox
	}

	for _, inter := range interfaces {
		hardwareAddr := inter.HardwareAddr.String()
		if hardwareAddr == "" {
			continue
		}

		isVirtual := false
		for _, prefix := range virtualMacPrefixes {
			if strings.HasPrefix(hardwareAddr, strings.ToLower(prefix)) {
				isVirtual = true
				break
			}
		}
		if isVirtual {
			continue
		}

		switch {
		case strings.HasPrefix(inter.Name, "en"), strings.HasPrefix(inter.Name, "Ethernet"), strings.HasPrefix(inter.Name, "以太网"):
			macAddress = append(macAddress, hardwareAddr)
		case strings.HasPrefix(inter.Name, "Bluetooth"), strings.HasSuffix(inter.Name, "Bluetooth"), strings.HasPrefix(inter.Name, "蓝牙网络连接"):
			bluetoothAddress = append(bluetoothAddress, hardwareAddr)
		}
	}

	if len(macAddress) == 0 {
		macAddress = append(macAddress, bluetoothAddress...)
		if len(macAddress) == 0 {
			//fmt.Printf(red, "no mac address found,Please contact customer service")
			//_, _ = fmt.Scanln()
			//return macErrorStr
			return getMacMD5_241019()
		}
	}
	sort.Strings(macAddress)
	return fmt.Sprintf("%x", md5.Sum([]byte(strings.Join(macAddress, ","))))
}
func getMacMD5_241019() string {
	id, err := machineid.ID()
	if err != nil {
		return err.Error()
	}
	id = strings.ToLower(id)
	id = strings.ReplaceAll(id, "-", "")
	return id
}

func getLocale() (langRes, locRes string) {
	osHost := runtime.GOOS
	langRes = "en"
	locRes = "US"
	switch osHost {
	case "windows":
		// Exec powershell Get-Culture on Windows.
		cmd := exec.Command("powershell", "Get-Culture | select -exp Name")
		output, err := cmd.Output()
		if err == nil {
			langLocRaw := strings.TrimSpace(string(output))
			langLoc := strings.Split(langLocRaw, "-")
			langRes = langLoc[0]
			langRes = strings.Split(langRes, "-")[0]
			locRes = langLoc[1]
			return
		}
	case "darwin":
		// Exec shell Get-Culture on MacOS.
		cmd := exec.Command("sh", "osascript -e 'user locale of (get system info)'")
		output, err := cmd.Output()
		if err == nil {
			langLocRaw := strings.TrimSpace(string(output))
			langLoc := strings.Split(langLocRaw, "_")
			langRes = langLoc[0]
			langRes = strings.Split(langRes, "-")[0]
			if len(langLoc) == 1 {
				return
			}
			locRes = langLoc[1]
			return
		}
		plistB, err := os.ReadFile(os.Getenv("HOME") + "/Library/Preferences/.GlobalPreferences.plist")
		if err != nil {
			panic(err)
		}
		var a map[string]interface{}
		_, err = plist.Unmarshal(plistB, &a)
		if err != nil {
			panic(err)
		}
		langLocRaw := a["AppleLocale"].(string)
		langLoc := strings.Split(langLocRaw, "_")
		langRes = langLoc[0]
		langRes = strings.Split(langRes, "-")[0]
		if len(langLoc) == 1 {
			return
		}
		locRes = langLoc[1]
		return
	case "linux":
		envlang, ok := os.LookupEnv("LANG")
		if ok {
			langLocRaw := strings.TrimSpace(envlang)
			langLocRaw = strings.Split(envlang, ".")[0]
			langLoc := strings.Split(langLocRaw, "_")
			langRes = langLoc[0]
			langRes = strings.Split(langRes, "-")[0]
			if len(langLoc) == 1 {
				return
			}
			locRes = langLoc[1]
			return
		}
	}
	if langRes == "" {
		langLocRaw := os.Getenv("LC_CTYPE")
		langLocRaw = strings.Split(langLocRaw, ".")[0]
		langLoc := strings.Split(langLocRaw, "_")
		langRes = langLoc[0]
		langRes = strings.Split(langRes, "-")[0]
		if len(langLoc) == 1 {
			return
		}
		locRes = langLoc[1]
		return
	}
	return
}
