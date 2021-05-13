package pt.ubi.di.security.model;

import java.util.Arrays;

/**
 *  plaintext   |  16B   |   4B  |        20B         |
 *  message     | secret | index | SHA1(secret|index) |
 *
 *  random     |    20B     |       20B      |
 *   noise     | SHA1(key) | SHA1(SHA1(key)) |
 *
 *  puzzle     |        40B        |       8B        |
 *             | message XOR noise | key(incomplete) |
 */
public class MerklePuzzle {
    private final byte[] puzzle;
    private final int sizeCipherMessage;
    private final int sizeKey;
    private final int sizeSecret;
    private final int totalSize;
    private final int bytesToGuess;

    public MerklePuzzle(byte[] puzzle, int sizeCipherMessage, int sizeKey,int bytesToGuess,int totalSize,int sizeSecret) {
        this.puzzle = puzzle;
        this.sizeCipherMessage = sizeCipherMessage;
        this.sizeKey = sizeKey;
        this.bytesToGuess = bytesToGuess;
        this.totalSize = totalSize;
        this.sizeSecret = sizeSecret;
    }

    public byte[] getPuzzle() {
        return puzzle;
    }

    public int getBytesToGuess() {
        return bytesToGuess;
    }

    public int getSizeCipherMessage() {
        return sizeCipherMessage;
    }

    public int getSizeKey() {
        return sizeKey;
    }

    public int getSizeSecret() {
        return sizeSecret;
    }

    public int getTotalSize() {
        return totalSize;
    }

    @Override
    public String toString() {
        return "MerklePuzzle{" +
                "puzzle=" + Arrays.toString(puzzle) +
                ", sizeCipherMessage=" + sizeCipherMessage +
                ", sizeKey=" + sizeKey +
                ", totalSize=" + totalSize +
                ", bytesToGuess=" + bytesToGuess +
                '}';
    }
}
