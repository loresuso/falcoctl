package cmd

import (
	"github.com/falcosecurity/falcoctl/pkg/index"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/falcosecurity/falcoctl/cmd/internal/validate"
	"github.com/falcosecurity/falcoctl/pkg/repo"
	utils "github.com/falcosecurity/falcoctl/pkg/utils"
	"github.com/go-playground/validator/v10"
	"github.com/mitchellh/go-homedir"
	logger "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// Defaults
const (
	defaultIndexFile = "index.yaml"
)

var _ CommandOptions = &RepoUpdateOptions{}

// RepoUpdateOptions represents the `repo update` command options
type RepoUpdateOptions struct {
	IndexFile string
}

// AddFlags adds flag to c
func (o *RepoUpdateOptions) AddFlags(c *cobra.Command) {
}

// Validate validates the `repo update` command options
func (o *RepoUpdateOptions) Validate(c *cobra.Command, args []string) error {
	if err := validate.V.Struct(o); err != nil {
		return err.(validator.ValidationErrors)
	}
	return nil
}

// NewRepoAddOptions instantiates the `repo add` command options
func NewRepoUpdateOptions() *RepoUpdateOptions {
	return &RepoUpdateOptions{
		IndexFile: defaultIndexFile,
	}
}

func NewRepoUpdateCmd(options CommandOptions) *cobra.Command {
	o := options.(*RepoOptions)

	cmd := &cobra.Command{
		Use:                   "update",
		DisableFlagsInUseLine: true,
		Short:                 "Update repository",
		Long:                  "Update a repository and download the corresponding index",
		PreRunE:               o.Validate,
		RunE: func(cmd *cobra.Command, args []string) error {

			home, err := homedir.Dir()
			if err != nil {
				logger.WithError(err).Fatal("error getting the home directory")
			}

			file := filepath.Join(home, o.RepoPath, o.RepoFile)
			r, err := repo.LoadRepos(file)
			if err != nil {
				if os.IsNotExist(err) {
					r = &repo.RepoList{}
				} else {

					logger.Fatal(err.Error())
					return err
				}
			}

			for i := 0; i < len(r.Sources); i++ {
				//TODO printing update effect? Successes/failures etc...
				repository := &r.Sources[i]
				u, err := url.Parse(repository.Url)
				if err != nil {
					logger.WithError(err).Fatal("cannot parse index url")
					return err
				}
				u.Path = path.Join(u.Path, o.IndexFile)
				parsedUrl := u.String()
				resp, err := utils.DownloadFile(parsedUrl)
				if err != nil {
					logger.WithError(err).Fatal("Cannot download file")
					return err
				}
				data, err := io.ReadAll(resp.Body)
				if err != nil {
					logger.WithError(err).Fatal("cannot read index file")
					return err
				}
				_, err = index.ValidateIndex(data)
				if err != nil {
					logger.WithError(err).Fatal("cannot parse index")
					return err
				}

				wpath := filepath.Join(home, o.RepoPath, repository.Name+".yaml")
				err = utils.SaveToFile(data, wpath)
				if err != nil {
					logger.WithError(err).Fatal("cannot write index file")
				}
				repository.Date = time.Now().Format(repo.Timeformat)
			}

			err = repo.WriteRepos(file, r)
			if err != nil {
				logger.WithError(err).Fatal("cannot write repository file")
				return err
			}

			return nil
		},
	}
	o.RepoUpdateOptions.AddFlags(cmd)
	return cmd
}
