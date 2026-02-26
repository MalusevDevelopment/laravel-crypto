<?php

declare(strict_types=1);

namespace CodeLieutenant\LaravelCrypto\Support;

use Illuminate\Support\Facades\Crypt;

class EncryptedFile
{
    private string $encryptedPath;

    private ?string $decryptedPath = null;

    private ?string $originalHash = null;

    private bool $isDirty = false;

    public function __construct(string $encryptedPath)
    {
        $this->encryptedPath = $encryptedPath;
    }

    /**
     * Get the decrypted path of the file.
     * Decrypts the file to a temporary location if not already decrypted.
     */
    public function getDecryptedPath(): string
    {
        if ($this->decryptedPath === null) {
            $this->decryptedPath = tempnam(sys_get_temp_dir(), 'laravel-crypto-dec');
            if (file_exists($this->encryptedPath)) {
                Crypt::decryptFile($this->encryptedPath, $this->decryptedPath);
            }
            $this->originalHash = $this->calculateHash();
        }

        return $this->decryptedPath;
    }

    /**
     * Check if the file is dirty (content changed or path changed).
     */
    public function isDirty(): bool
    {
        if ($this->isDirty) {
            return true;
        }

        if ($this->decryptedPath === null) {
            return false;
        }

        if (! file_exists($this->decryptedPath)) {
            return true;
        }

        return $this->calculateHash() !== $this->originalHash;
    }

    /**
     * Calculate hash of the decrypted file.
     */
    private function calculateHash(): ?string
    {
        if (! file_exists($this->decryptedPath)) {
            return null;
        }

        return hash_file('sha256', $this->decryptedPath);
    }

    /**
     * Get the encrypted path of the file.
     */
    public function getEncryptedPath(): string
    {
        return $this->encryptedPath;
    }

    /**
     * Get a stream of the decrypted file.
     *
     * @return resource
     */
    public function stream()
    {
        $path = $this->getDecryptedPath();
        $stream = fopen($path, 'rb');

        if ($stream === false) {
            throw new \RuntimeException(sprintf('Failed to open stream for decrypted file: %s', $path));
        }

        return $stream;
    }

    /**
     * Get the contents of the decrypted file.
     */
    public function contents(): string
    {
        return file_get_contents($this->getDecryptedPath());
    }

    /**
     * Put contents into the decrypted file.
     */
    public function putContents(string $content): self
    {
        file_put_contents($this->getDecryptedPath(), $content);
        $this->isDirty = true;

        return $this;
    }

    /**
     * Delete both encrypted and decrypted files.
     */
    public function delete(): void
    {
        if (file_exists($this->encryptedPath)) {
            unlink($this->encryptedPath);
        }

        if ($this->decryptedPath && file_exists($this->decryptedPath)) {
            unlink($this->decryptedPath);
            $this->decryptedPath = null;
        }
    }

    /**
     * Set a new encrypted path for the file.
     */
    public function setEncryptedPath(string $path): self
    {
        if ($this->encryptedPath !== $path) {
            // If we haven't decrypted the file yet, we should do it now before we lose the old path
            if ($this->decryptedPath === null && file_exists($this->encryptedPath)) {
                $this->getDecryptedPath();
            }
            $this->encryptedPath = $path;
            $this->isDirty = true;
        }

        return $this;
    }

    /**
     * Set a new decrypted path for the file.
     */
    public function setDecryptedPath(string $path): self
    {
        // Use a user-provided file as the source for the new encrypted file
        if ($this->decryptedPath && file_exists($this->decryptedPath)) {
            unlink($this->decryptedPath);
        }
        $this->decryptedPath = $path;
        $this->isDirty = true;
        // Since we are setting a new decrypted path, we don't have an original hash for it relative to the encrypted one
        $this->originalHash = null;

        return $this;
    }

    public function __destruct()
    {
        if ($this->decryptedPath && file_exists($this->decryptedPath) && str_starts_with($this->decryptedPath, sys_get_temp_dir())) {
            unlink($this->decryptedPath);
        }
    }

    public function __toString(): string
    {
        return $this->encryptedPath;
    }
}
