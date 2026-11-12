// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package walker holds the trivy walkers
package walker

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/utils"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
	"github.com/samber/lo"
)

var defaultSkipDirs = []string{
	"**/.git",
	"proc",
	"sys",
	"dev",
}

// FSWalker is the filesystem walker used for SBOM generation. It walks the
// filesystem at its root, and the static paths of Trivy's analyzers inside
// that root.
type FSWalker struct {
	root string
}

// NewFSWalker returns a walker of the filesystem at root.
func NewFSWalker(root string) *FSWalker {
	return &FSWalker{root: filepath.Clean(root)}
}

func cleanSkipPaths(root string, skipPaths []string) []string {
	skipPaths = lo.Map(skipPaths, func(skipPath string, _ int) string {
		if strings.HasPrefix(skipPath, root) {
			if relPath, err := filepath.Rel(root, skipPath); err == nil {
				return relPath
			}
		}
		return skipPath
	})
	return utils.CleanSkipPaths(skipPaths)
}

// Walk walks the filesystem at rootPath, calling fn for each unfiltered file.
// Trivy's static-paths mechanism calls Walk with a file or directory inside
// the root, which Walk resolves inside the root: a link there may lead
// anywhere in the root and nowhere outside it.
func (w *FSWalker) Walk(ctx context.Context, rootPath string, opt walker.Option, fn walker.WalkFunc) error {
	static := filepath.Clean(rootPath) != w.root
	// Every path lies inside /, so a static path there resolves as the
	// system resolves it, through absolute links too, which os.Root takes
	// for escapes.
	if static && w.root != "/" {
		return w.walkStatic(ctx, rootPath, opt, fn)
	}

	info, err := os.Stat(rootPath)
	if errors.Is(err, os.ErrNotExist) || (static && absent(err)) {
		return nil
	}
	if err != nil {
		return xerrors.Errorf("failed to stat root %s: %w", rootPath, err)
	}

	if !info.IsDir() {
		return w.walkFile(ctx, info, func() (xio.ReadSeekCloserAt, error) { return os.Open(rootPath) }, opt, fn)
	}

	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return xerrors.Errorf("failed to open root %s: %w", rootPath, err)
	}
	defer root.Close()

	return w.walkDir(ctx, root, ".", rootPath, opt, fn)
}

// walkStatic walks name, a file or directory inside the root.
func (w *FSWalker) walkStatic(ctx context.Context, name string, opt walker.Option, fn walker.WalkFunc) error {
	rel, err := filepath.Rel(w.root, name)
	if err != nil || !filepath.IsLocal(rel) {
		return xerrors.Errorf("failed to walk %s: outside of the root %s", name, w.root)
	}

	root, err := os.OpenRoot(w.root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return xerrors.Errorf("failed to open root %s: %w", w.root, err)
	}
	defer root.Close()

	info, err := root.Stat(rel)
	if absent(err) {
		return nil
	}
	if err != nil {
		return xerrors.Errorf("failed to stat root %s: %w", name, err)
	}

	if !info.IsDir() {
		return w.walkFile(ctx, info, func() (xio.ReadSeekCloserAt, error) { return root.Open(rel) }, opt, fn)
	}
	return w.walkDir(ctx, root, rel, name, opt, fn)
}

// absent reports whether err, from resolving a path inside the root, means
// that the path names nothing there. os.Root fails with ELOOP past 8 links
// and with ENAMETOOLONG past 255 steps and 8 .. restarts. A link that leaves
// the root fails with os.Root's own error, the one error here without an
// Errno inside.
func absent(err error) bool {
	if err == nil {
		return false
	}
	var errno syscall.Errno
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) ||
		errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.ELOOP) ||
		errors.Is(err, syscall.ENAMETOOLONG) || !errors.As(err, &errno)
}

// walkDir walks the directory dir, which is base inside root.
func (w *FSWalker) walkDir(ctx context.Context, root *os.Root, base, dir string, opt walker.Option, fn walker.WalkFunc) error {
	opt.SkipDirs = append(opt.SkipDirs, defaultSkipDirs...)

	opt.SkipDirs = cleanSkipPaths(dir, opt.SkipDirs)
	opt.SkipFiles = cleanSkipPaths(dir, opt.SkipFiles)
	opt.OnlyDirs = cleanSkipPaths(dir, opt.OnlyDirs)

	prefetchCtx, cancel := context.WithCancel(ctx)
	var prefetched sync.WaitGroup
	prefetched.Go(func() { walker.Prefetch(prefetchCtx, os.DirFS(dir), opt, walker.PrefetchWorkers) })
	defer prefetched.Wait()
	defer cancel()

	walkDirFunc := w.walkDirFunc(ctx, root, base, fn, opt)
	walkDirFunc = w.onError(walkDirFunc, opt)

	// The trailing separator makes the walk follow a dir that is a symbolic
	// link, such as /proc/<pid>/root.
	top := dir + string(filepath.Separator)
	err := filepath.WalkDir(top, func(p string, d fs.DirEntry, err error) error {
		rel, relErr := filepath.Rel(top, p)
		if relErr != nil {
			return relErr
		}
		return walkDirFunc(rel, d, err)
	})
	if err != nil {
		return xerrors.Errorf("walk dir error: %w", err)
	}

	return nil
}

func (w *FSWalker) walkFile(ctx context.Context, info os.FileInfo, opener func() (xio.ReadSeekCloserAt, error), opt walker.Option, fn walker.WalkFunc) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if !info.Mode().IsRegular() {
		return nil
	}

	// Match upstream Trivy semantics: for a single-file root, filepath.Rel(root, root)
	// returns "." and that is what gets passed through to the analyzer.
	const relPath = "."

	if err := fn(ctx, relPath, info, opener); err != nil {
		if opt.ErrorCallback != nil {
			if cberr := opt.ErrorCallback(relPath, err); cberr == nil {
				return nil
			}
		}
		return xerrors.Errorf("failed to analyze file: %w", err)
	}
	return nil
}

// walkDirFunc is the type of the function called by [WalkDir] to visit
// each file or directory.
func (w *FSWalker) walkDirFunc(ctx context.Context, root *os.Root, base string, fn walker.WalkFunc, opt walker.Option) fs.WalkDirFunc {
	return func(filePath string, d fs.DirEntry, err error) error {
		// The analyzers check the context only for the files they read,
		// so check it here to stop a walk through files no analyzer wants.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// A listing by path stops at PATH_MAX, as do the post-analyzers,
		// which open files by path, so the walk passes over what lies beyond.
		if err != nil {
			if errors.Is(err, fs.ErrPermission) || errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENAMETOOLONG) {
				return nil
			}
			return err
		}

		filePath = filepath.ToSlash(filePath)

		// Skip unnecessary files
		switch {
		case d.IsDir():
			if utils.SkipPath(filePath, opt.SkipDirs) {
				return fs.SkipDir
			}
			if utils.OnlyPath(filePath, opt.OnlyDirs) {
				return fs.SkipDir
			}
			return nil
		case !opt.AllFiles && !d.Type().IsRegular():
			return nil
		case utils.SkipPath(filePath, opt.SkipFiles):
			return nil
		case utils.OnlyPath(filePath, opt.OnlyDirs):
			return nil
		}

		info, err := d.Info()
		if errors.Is(err, syscall.ENAMETOOLONG) {
			// A file past PATH_MAX, as above.
			return nil
		}
		if err != nil {
			return xerrors.Errorf("file info error: %w", err)
		}

		if err = fn(ctx, filePath, info, fileOpener(root, path.Join(base, filePath))); err != nil {
			return xerrors.Errorf("failed to analyze file: %w", err)
		}

		return nil
	}
}

func (w *FSWalker) onError(wrapped fs.WalkDirFunc, opt walker.Option) fs.WalkDirFunc {
	return func(filePath string, d fs.DirEntry, err error) error {
		err = wrapped(filePath, d, err)
		switch {
		// Unwrap fs.SkipDir error
		case errors.Is(err, fs.SkipDir):
			return fs.SkipDir
		// Ignore permission errors
		case os.IsPermission(err):
			return nil
		// Stop when the context is done, whatever the error callback says
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return xerrors.Errorf("stopped at %s: %w", filePath, err)
		case err != nil:
			if opt.ErrorCallback != nil {
				err = opt.ErrorCallback(filePath, err)
				if err == nil {
					return nil
				}
			}
			// halt traversal on any other error
			return xerrors.Errorf("unknown error with %s: %w", filePath, err)
		}
		return nil
	}
}

// fileOpener returns a function opening a file.
func fileOpener(root *os.Root, filePath string) func() (xio.ReadSeekCloserAt, error) {
	return func() (xio.ReadSeekCloserAt, error) {
		return root.Open(filePath)
	}
}
