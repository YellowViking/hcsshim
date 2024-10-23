//go:build linux
// +build linux

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/Microsoft/hcsshim/pkg/amdsevsnp"
)

// verboseReport returns formatted attestation report.
func verboseReport(r amdsevsnp.Report) string {
	fieldNameFmt := "%-20s"
	pretty := ""
	pretty += fmt.Sprintf(fieldNameFmt+"%08x\n", "Version", r.Version)
	pretty += fmt.Sprintf(fieldNameFmt+"%08x\n", "GuestSVN", r.GuestSVN)
	pretty += fmt.Sprintf(fieldNameFmt+"%016x\n", "Policy", r.Policy)
	pretty += fmt.Sprintf(fieldNameFmt+"%s\n", "FamilyID", r.FamilyID)
	pretty += fmt.Sprintf(fieldNameFmt+"%s\n", "ImageID", r.ImageID)
	pretty += fmt.Sprintf(fieldNameFmt+"%08x\n", "VMPL", r.VMPL)
	pretty += fmt.Sprintf(fieldNameFmt+"%08x\n", "SignatureAlgo", r.SignatureAlgo)
	pretty += fmt.Sprintf(fieldNameFmt+"%016x\n", "PlatformVersion", r.PlatformVersion)
	pretty += fmt.Sprintf(fieldNameFmt+"%016x\n", "PlatformInfo", r.PlatformInfo)
	pretty += fmt.Sprintf(fieldNameFmt+"%08x\n", "AuthorKeyEn", r.AuthorKeyEn)
	pretty += fmt.Sprintf(fieldNameFmt+"%s\n", "ReportData", r.ReportData)
	pretty += fmt.Sprintf(fieldNameFmt+"%s\n", "Measurement", r.Measurement)
	pretty += fmt.Sprintf(fieldNameFmt+"%x\n", "HostData", r.HostData)
	pretty += fmt.Sprintf(fieldNameFmt+"%s\n", "IDKeyDigest", r.IDKeyDigest)
	pretty += fmt.Sprintf(fieldNameFmt+"%s\n", "AuthorKeyDigest", r.AuthorKeyDigest)
	pretty += fmt.Sprintf(fieldNameFmt+"%s\n", "ReportID", r.ReportID)
	pretty += fmt.Sprintf(fieldNameFmt+"%s\n", "ReportIDMA", r.ReportIDMA)
	pretty += fmt.Sprintf(fieldNameFmt+"%016x\n", "ReportTCB", r.ReportTCB)
	pretty += fmt.Sprintf(fieldNameFmt+"%s\n", "ChipID", r.ChipID)
	pretty += fmt.Sprintf(fieldNameFmt+"%s\n", "CommittedSVN", r.CommittedSVN)
	pretty += fmt.Sprintf(fieldNameFmt+"%s\n", "CommittedVersion", r.CommittedVersion)
	pretty += fmt.Sprintf(fieldNameFmt+"%s\n", "LaunchSVN", r.LaunchSVN)
	pretty += fmt.Sprintf(fieldNameFmt+"%s\n", "Signature", r.Signature)
	return pretty
}

func main() {
	reportDataFlag := flag.String(
		"report-data",
		"",
		"Report data to use when fetching SNP attestation report",
	)
	binaryFmtFlag := flag.Bool(
		"binary",
		false,
		"Fetch report in binary format",
	)
	verbosePrintFlag := flag.Bool(
		"verbose",
		false,
		"Print report in a prettier format",
	)

	flag.Parse()

	fmt.Println("test my snp-report")

	var reportBytes []byte
	if *reportDataFlag != "" {
		var err error
		reportBytes, err = hex.DecodeString(*reportDataFlag)
		if err != nil {
			fmt.Printf("failed to decode report data:%s\n", err)
			os.Exit(1)
		}
	}
	if *binaryFmtFlag {
		var binaryReport []byte
		var err error
		binaryReport, err = amdsevsnp.FetchRawSNPReport(reportBytes)
		fmt.Printf("FetchRawSNPReport fetched successfully\n")
		if err != nil {
			fmt.Println(err)
		}
		fmt.Printf("%x\n", binaryReport)
	}

	var report amdsevsnp.Report
	var err error
	report, err = amdsevsnp.FetchParsedSNPReport(reportBytes)
	fmt.Printf("FetchParsedSNPReport fetched successfully\n")
	if err != nil {
		fmt.Printf("failed to fetch SNP report: %s", err)
	}

	fmt.Printf("Report fetched successfully\n")

	var customData [64]byte
	// fill with zeros
	for i := range customData {
		customData[i] = 0
	}
	var derived []byte
	fmt.Printf("starting to fetch derived key\n")
	derived, err = amdsevsnp.FetchDerivedKey(0)
	if err != nil {
		fmt.Printf("failed to fetch derived key: %s", err)
	} else {
		fmt.Printf("Derived key: %x\n", derived)
	}
	customData[0] = 1
	derived, err = amdsevsnp.FetchDerivedKey(1)
	if err != nil {
		fmt.Printf("failed to fetch derived key: %s", err)
	} else {
		fmt.Printf("Derived key with customData[0] == 1: %x\n", derived)
	}

	if !*verbosePrintFlag {
		fmt.Printf("%+v\n", report)
	} else {
		fmt.Println(verboseReport(report))
	}
}
