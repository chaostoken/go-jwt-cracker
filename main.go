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
	"sync"
	"time"

	tg "github.com/go-telegram-bot-api/telegram-bot-api"
	"github.com/urfave/cli/v2"
)



func main() {
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
		numberCh = make(chan *big.Int)
		findCh = make(chan struct{})
	)

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

			// generate combinations
			combine := NewCombinator(elems,maxChar)

			current := big.NewInt(1)
			if startID != 0 {
				current = big.NewInt(startID)
			}

			// logging attempts
			go func() {
				ticker := time.NewTicker(1 * time.Minute)
				for range ticker.C {
					// race condition when reading current but that not critical
					log.Printf("check %d combinations", current)
				}
			}()
			log.Printf("all combinations %d \n", combine.CombinationsCount())

			// send numbers
			go func(){
				for {
					select {
					case <-findCh:
						close(numberCh)
						return
					default:
						if current.Cmp(combine.CombinationsCount()) == -1 {
							numberCh<-current
							current = new(big.Int).Add(current,one)
						} else {
							close(numberCh)
							return
						}
					}
				}
			}()

			// decode token
			parts := strings.Split(token, ".")
			message := []byte(parts[0] + "." + parts[1])
			sign := make([]byte, base64.RawURLEncoding.DecodedLen(len(parts[2])))
			base64.RawURLEncoding.Decode(sign, []byte(parts[2]))

			var wg sync.WaitGroup
			wg.Add(countWorkers)
			for i := 0; i < countWorkers; i++ {
				go func() {
					for number := range numberCh {
						combo := combine.ComboFromBigint(number)
						hasher := hmac.New(sha256.New, []byte(combo))
						hasher.Write(message)
						sum := hasher.Sum(nil)

						if bytes.Equal(sign, sum) {
							text := "[+] Valid secret found: " + combo
							if enableNotify {
								client.Send(tg.NewMessage(tgChat, text))
							}
							log.Println(text)
							findCh<- struct{}{}
							break
						}
					}
					wg.Done()
				}()
			}

			wg.Wait()

			log.Println("Finished! (((")
			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

type Combinator struct {
	regs, totalRegs []*big.Int
	elems []string
}

func NewCombinator(elems []string, length int) *Combinator {
	c := new(Combinator)
	c.elems = elems
	alphabetCount := big.NewInt(int64(len(elems)))

	combinations := big.NewInt(0)
	for r := 0; length >= 0; r++ {
		regNumber := new(big.Int).Exp(alphabetCount, big.NewInt(int64(r)), nil)
		combinations = new(big.Int).Add(combinations, regNumber)
		c.regs = append(c.regs, regNumber)
		c.totalRegs = append(c.totalRegs, combinations)
		length--
	}

	// reverse
	for i, j := 0, len(c.regs)-1; i < j; i, j = i+1, j-1 {
		c.regs[i], c.regs[j] = c.regs[j], c.regs[i]
	}
	for i, j := 0, len(c.totalRegs)-1; i < j; i, j = i+1, j-1 {
		c.totalRegs[i], c.totalRegs[j] = c.totalRegs[j], c.totalRegs[i]
	}
	return c
}

func (c *Combinator) ComboFromBigint(current *big.Int) string {
	x := new(big.Int).Set(current)
	var combo string
	for i, tr := range c.totalRegs {
		if x.Cmp(tr) == -1 {
			continue
		}

		r := c.regs[i]
		n := new(big.Int).Div(x, r).Int64()

		// x - n*r
		nr := new(big.Int).Mul(big.NewInt(-n), r)
		xnr := new(big.Int).Add(x, nr)

		// x-n*r < totalRegs[i+1]
		if i < len(c.totalRegs)-1 && xnr.Cmp(c.totalRegs[i+1]) == -1 {
			n = n - 1
			nr = new(big.Int).Mul(big.NewInt(-n), r)
			xnr = new(big.Int).Add(x, nr)
		}

		x = new(big.Int).Set(xnr)
		combo = combo + c.elems[n-1]
	}
	return combo
}

func (c *Combinator) CombinationsCount() *big.Int {
	return c.totalRegs[0]
}