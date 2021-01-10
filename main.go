package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	tg "github.com/go-telegram-bot-api/telegram-bot-api"
	"github.com/urfave/cli/v2"
)

var (
	token        string
	charset      string
	maxChar      int
	startID      int64
	countWorkers int
	tgChat       int64
	tgToken      string

	keywordListFile string

	one    = big.NewInt(1)
	combCh = make(chan string)
)

func main() {
	quit := make(chan struct{})
	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "token",
				Aliases:     []string{"t"},
				Usage:       "The JWT token you want to crack",
				Value:       "",
				EnvVars:     []string{"JWT_TOKEN"},
				Destination: &token,
			},
			&cli.StringFlag{
				Name:        "charset",
				Aliases:     []string{"ch"},
				Usage:       "The charset to use during bruteforce",
				Value:       "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
				EnvVars:     []string{"CHARSET"},
				Destination: &charset,
			},
			&cli.IntFlag{
				Name:        "max",
				Aliases:     []string{"m"},
				Usage:       "Max chars in token",
				Value:       12,
				EnvVars:     []string{"MAX_CHAR"},
				Destination: &maxChar,
			},
			&cli.Int64Flag{
				Name:        "start_id",
				Aliases:     []string{"id"},
				Usage:       "The start id of combination",
				Destination: &startID,
			},
			&cli.IntFlag{
				Name:        "count_workers",
				Aliases:     []string{"cw"},
				Usage:       "Max workers for check JWT",
				Value:       2,
				EnvVars:     []string{"COUNT_WORKERS"},
				Destination: &countWorkers,
			},
			&cli.Int64Flag{
				Name:        "tg_chat",
				Aliases:     []string{"tgch"},
				Usage:       "Tg chat for notify",
				EnvVars:     []string{"TG_USER"},
				Destination: &tgChat,
			},
			&cli.StringFlag{
				Name:        "tg_token",
				Aliases:     []string{"tgt"},
				Usage:       "Tg token for notify",
				EnvVars:     []string{"TG_TOKEN"},
				Destination: &tgToken,
			},
			&cli.StringFlag{
				Name:        "wordlist",
				Aliases:     []string{"w"},
				Usage:       "wordlist to use during bruteforce",
				Destination: &keywordListFile,
			},
		},
		Name:  "go-jwt-cracker",
		Usage: "This is a simple tool used to bruteforce HMAC secret keys in JWT tokens!",
		Action: func(c *cli.Context) error {
			// notify configuration
			var enableNotify bool
			var client *tg.BotAPI
			var err error
			if tgChat != 0 && tgToken != "" {
				enableNotify = true
				client, err = tg.NewBotAPI(tgToken)
				if err != nil {
					return err
				}
				defer client.Send(tg.NewMessage(tgChat, "job finished"))
			}

			if token == "" {
				return fmt.Errorf(`need set token for cracking`)
			}

			if enableNotify {
				client.Send(tg.NewMessage(tgChat, "start from go-jwt-cracker"))
			}

			elems := make([]string, 0)
			if keywordListFile == "" {
				elems = make([]string, len(charset))
				for i, r := range charset {
					elems[i] = string(r)
				}
			} else {
				wordlistFile, _ := os.Open(keywordListFile)
				defer wordlistFile.Close()

				scanner := bufio.NewScanner(wordlistFile)
				scanner.Split(bufio.ScanLines)

				for scanner.Scan() {
					elems = append(elems, scanner.Text())
				}
			}

			go func() {
				generateCombinations(elems, maxChar)
				close(quit)
			}()

			// decode token
			parts := strings.Split(token, ".")
			message := []byte(parts[0] + "." + parts[1])
			//sign := []byte(parts[2])
			sign := make([]byte, base64.RawURLEncoding.DecodedLen(len(parts[2])))
			base64.RawURLEncoding.Decode(sign, []byte(parts[2]))

			for i := 0; i < countWorkers; i++ {
				go func() {
					for combo := range combCh {
						hasher := hmac.New(sha256.New, []byte(combo))
						hasher.Write(message)
						sum := hasher.Sum(nil)

						if bytes.Equal(sign, sum) {
							text := "[+] Valid secret found: " + combo
							if enableNotify {
								client.Send(tg.NewMessage(tgChat, text))
							}
							log.Println(text)
							break
						}
					}
					close(quit)
				}()
			}

			<-quit

			log.Println("Finished! (((")
			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func generateCombinations(elems []string, length int) {
	countChars := len(elems)
	current := big.NewInt(1)
	if startID != 0 {
		current = big.NewInt(startID)
	}

	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		for range ticker.C {
			// race condition when reading current but that not critical
			log.Printf("check %d combinations", current)
		}
	}()

	combinations := big.NewInt(0)
	alphabetCount := big.NewInt(int64(countChars))
	var regs, totalRegs []*big.Int
	for r := 0; length >= 0; r++ {
		regNumber := new(big.Int).Exp(alphabetCount, big.NewInt(int64(r)), nil)
		combinations = new(big.Int).Add(combinations, regNumber)
		regs = append(regs, regNumber)
		totalRegs = append(totalRegs, combinations)
		length--
	}

	// reverse
	for i, j := 0, len(regs)-1; i < j; i, j = i+1, j-1 {
		regs[i], regs[j] = regs[j], regs[i]
	}
	for i, j := 0, len(totalRegs)-1; i < j; i, j = i+1, j-1 {
		totalRegs[i], totalRegs[j] = totalRegs[j], totalRegs[i]
	}

	log.Printf("all combinations %d \n", combinations)

	for current.Cmp(combinations) == -1 {
		x := new(big.Int).Set(current)
		var combo string
		for i, tr := range totalRegs {
			if current.Cmp(tr) == -1 {
				continue
			}

			r := regs[i]
			n := new(big.Int).Div(x, r).Int64()

			// x - n*r
			nr := new(big.Int).Mul(big.NewInt(-n), r)
			xnr := new(big.Int).Add(x, nr)

			// x-n*r < totalRegs[i+1]
			if i < len(totalRegs)-1 && xnr.Cmp(totalRegs[i+1]) == -1 {
				n = n - 1
				nr = new(big.Int).Mul(big.NewInt(-n), r)
				xnr = new(big.Int).Add(x, nr)
			}

			x = new(big.Int).Set(xnr)
			combo = combo + elems[n-1]
		}
		combCh <- combo
		current = new(big.Int).Add(current, one)
	}
}
