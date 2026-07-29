import { useEffect, useRef, useState } from "react";

export const REVEAL_DIRECTION = {
  START: "start",
  END: "end",
  CENTER: "center",
} as const;

export const DECRYPTED_TEXT_ANIMATE_ON = {
  VIEW: "view",
  HOVER: "hover",
  IN_VIEW_HOVER: "inViewHover",
  CLICK: "click",
} as const;

export const DECRYPTED_TEXT_CLICK_MODE = {
  ONCE: "once",
  TOGGLE: "toggle",
} as const;

const DIRECTION = {
  FORWARD: "forward",
  REVERSE: "reverse",
} as const;

export type RevealDirection =
  (typeof REVEAL_DIRECTION)[keyof typeof REVEAL_DIRECTION];
export type DecryptedTextAnimateOn =
  (typeof DECRYPTED_TEXT_ANIMATE_ON)[keyof typeof DECRYPTED_TEXT_ANIMATE_ON];
export type DecryptedTextClickMode =
  (typeof DECRYPTED_TEXT_CLICK_MODE)[keyof typeof DECRYPTED_TEXT_CLICK_MODE];

export const DEFAULT_CHARACTERS =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()_+";

interface DecryptedTextControllerOptions {
  text: string;
  speed: number;
  maxIterations: number;
  sequential: boolean;
  revealDirection: RevealDirection;
  useOriginalCharsOnly: boolean;
  characters: string;
  animateOn: DecryptedTextAnimateOn;
  clickMode: DecryptedTextClickMode;
}

type Direction = (typeof DIRECTION)[keyof typeof DIRECTION];

function buildPool(
  text: string,
  characters: string,
  useOriginalCharsOnly: boolean,
): string[] {
  return useOriginalCharsOnly
    ? Array.from(new Set(text.split(""))).filter((char) => char !== " ")
    : characters.split("");
}

function shuffleText(
  originalText: string,
  revealed: Set<number>,
  pool: string[],
): string {
  return originalText
    .split("")
    .map((char, i) => {
      if (char === " ") return " ";
      if (revealed.has(i)) return originalText[i];
      return pool[Math.floor(Math.random() * pool.length)];
    })
    .join("");
}

function computeOrder(len: number, revealDirection: RevealDirection): number[] {
  const order: number[] = [];
  if (len <= 0) return order;
  if (revealDirection === "start") {
    for (let i = 0; i < len; i++) order.push(i);
    return order;
  }
  if (revealDirection === "end") {
    for (let i = len - 1; i >= 0; i--) order.push(i);
    return order;
  }
  const middle = Math.floor(len / 2);
  let offset = 0;
  while (order.length < len) {
    if (offset % 2 === 0) {
      const idx = middle + offset / 2;
      if (idx >= 0 && idx < len) order.push(idx);
    } else {
      const idx = middle - Math.ceil(offset / 2);
      if (idx >= 0 && idx < len) order.push(idx);
    }
    offset++;
  }
  return order.slice(0, len);
}

function fillAllIndices(len: number): Set<number> {
  const s = new Set<number>();
  for (let i = 0; i < len; i++) s.add(i);
  return s;
}

function removeRandomIndices(set: Set<number>, count: number): Set<number> {
  const arr = Array.from(set);
  for (let i = 0; i < count && arr.length > 0; i++) {
    const idx = Math.floor(Math.random() * arr.length);
    arr.splice(idx, 1);
  }
  return new Set(arr);
}

export function useDecryptedTextController({
  text,
  speed,
  maxIterations,
  sequential,
  revealDirection,
  useOriginalCharsOnly,
  characters,
  animateOn,
  clickMode,
}: DecryptedTextControllerOptions) {
  const [displayText, setDisplayText] = useState<string>(text);
  const [isAnimating, setIsAnimating] = useState<boolean>(false);
  const [revealedIndices, setRevealedIndices] = useState<Set<number>>(
    new Set(),
  );
  const [hasAnimated, setHasAnimated] = useState<boolean>(false);
  const [isDecrypted, setIsDecrypted] = useState<boolean>(
    animateOn !== "click",
  );
  const [direction, setDirection] = useState<Direction>(DIRECTION.FORWARD);

  const containerRef = useRef<HTMLSpanElement>(null);
  const orderRef = useRef<number[]>([]);
  const pointerRef = useRef<number>(0);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const pool = buildPool(text, characters, useOriginalCharsOnly);

  const triggerDecrypt = () => {
    if (sequential) {
      orderRef.current = computeOrder(text.length, revealDirection);
      pointerRef.current = 0;
    }
    setRevealedIndices(new Set());
    setDirection(DIRECTION.FORWARD);
    setIsAnimating(true);
  };

  const triggerReverse = () => {
    if (sequential) {
      orderRef.current = computeOrder(text.length, revealDirection)
        .slice()
        .reverse();
      pointerRef.current = 0;
    }
    setRevealedIndices(fillAllIndices(text.length));
    setDisplayText(shuffleText(text, fillAllIndices(text.length), pool));
    setDirection(DIRECTION.REVERSE);
    setIsAnimating(true);
  };

  useEffect(() => {
    if (!isAnimating) return;

    let currentIteration = 0;
    const effectPool = buildPool(text, characters, useOriginalCharsOnly);

    const getNextIndex = (revealedSet: Set<number>): number => {
      const textLength = text.length;
      switch (revealDirection) {
        case "start":
          return revealedSet.size;
        case "end":
          return textLength - 1 - revealedSet.size;
        case "center": {
          const middle = Math.floor(textLength / 2);
          const offset = Math.floor(revealedSet.size / 2);
          const nextIndex =
            revealedSet.size % 2 === 0 ? middle + offset : middle - offset - 1;

          if (
            nextIndex >= 0 &&
            nextIndex < textLength &&
            !revealedSet.has(nextIndex)
          ) {
            return nextIndex;
          }
          for (let i = 0; i < textLength; i++) {
            if (!revealedSet.has(i)) return i;
          }
          return 0;
        }
        default:
          return revealedSet.size;
      }
    };

    intervalRef.current = setInterval(() => {
      setRevealedIndices((prevRevealed) => {
        if (sequential) {
          if (direction === DIRECTION.FORWARD) {
            if (prevRevealed.size < text.length) {
              const nextIndex = getNextIndex(prevRevealed);
              const newRevealed = new Set(prevRevealed);
              newRevealed.add(nextIndex);
              setDisplayText(shuffleText(text, newRevealed, effectPool));
              return newRevealed;
            }
            clearInterval(intervalRef.current ?? undefined);
            setIsAnimating(false);
            setIsDecrypted(true);
            return prevRevealed;
          }
          if (pointerRef.current < orderRef.current.length) {
            const idxToRemove = orderRef.current[pointerRef.current++];
            const newRevealed = new Set(prevRevealed);
            newRevealed.delete(idxToRemove);
            setDisplayText(shuffleText(text, newRevealed, effectPool));
            if (newRevealed.size === 0) {
              clearInterval(intervalRef.current ?? undefined);
              setIsAnimating(false);
              setIsDecrypted(false);
            }
            return newRevealed;
          }
          clearInterval(intervalRef.current ?? undefined);
          setIsAnimating(false);
          setIsDecrypted(false);
          return prevRevealed;
        }

        if (direction === DIRECTION.FORWARD) {
          setDisplayText(shuffleText(text, prevRevealed, effectPool));
          currentIteration++;
          if (currentIteration >= maxIterations) {
            clearInterval(intervalRef.current ?? undefined);
            setIsAnimating(false);
            setDisplayText(text);
            setIsDecrypted(true);
          }
          return prevRevealed;
        }

        const currentSet =
          prevRevealed.size === 0 ? fillAllIndices(text.length) : prevRevealed;
        const removeCount = Math.max(
          1,
          Math.ceil(text.length / Math.max(1, maxIterations)),
        );
        const nextSet = removeRandomIndices(currentSet, removeCount);
        setDisplayText(shuffleText(text, nextSet, effectPool));
        currentIteration++;
        if (nextSet.size === 0 || currentIteration >= maxIterations) {
          clearInterval(intervalRef.current ?? undefined);
          setIsAnimating(false);
          setIsDecrypted(false);
          setDisplayText(shuffleText(text, new Set(), effectPool));
          return new Set();
        }
        return nextSet;
      });
    }, speed);

    return () => clearInterval(intervalRef.current ?? undefined);
  }, [
    isAnimating,
    text,
    speed,
    maxIterations,
    sequential,
    revealDirection,
    direction,
    characters,
    useOriginalCharsOnly,
  ]);

  const handleClick = () => {
    if (animateOn !== "click") return;

    if (clickMode === "once") {
      if (isDecrypted) return;
      triggerDecrypt();
    }

    if (clickMode === "toggle") {
      if (isDecrypted) {
        triggerReverse();
      } else {
        triggerDecrypt();
      }
    }
  };

  const triggerHoverDecrypt = () => {
    if (isAnimating) return;
    setRevealedIndices(new Set());
    setIsDecrypted(false);
    setDisplayText(text);
    setDirection(DIRECTION.FORWARD);
    setIsAnimating(true);
  };

  const resetToPlainText = () => {
    clearInterval(intervalRef.current ?? undefined);
    setIsAnimating(false);
    setRevealedIndices(new Set());
    setDisplayText(text);
    setIsDecrypted(true);
    setDirection(DIRECTION.FORWARD);
  };

  useEffect(() => {
    if (animateOn !== "view" && animateOn !== "inViewHover") return;
    if (typeof IntersectionObserver === "undefined") return;

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting && !hasAnimated) {
            if (sequential) {
              orderRef.current = computeOrder(text.length, revealDirection);
              pointerRef.current = 0;
            }
            setRevealedIndices(new Set());
            setDirection(DIRECTION.FORWARD);
            setIsAnimating(true);
            setHasAnimated(true);
          }
        });
      },
      { root: null, rootMargin: "0px", threshold: 0.1 },
    );

    const currentRef = containerRef.current;
    if (currentRef) observer.observe(currentRef);

    return () => {
      if (currentRef) observer.unobserve(currentRef);
    };
  }, [animateOn, hasAnimated, sequential, text, revealDirection]);

  useEffect(() => {
    if (animateOn === "click") {
      const emptySet = new Set<number>();
      setRevealedIndices(emptySet);
      setDisplayText(
        shuffleText(text, emptySet, buildPool(text, characters, false)),
      );
      setIsDecrypted(false);
    } else {
      setRevealedIndices(new Set());
      setDisplayText(text);
      setIsDecrypted(true);
    }
    setDirection(DIRECTION.FORWARD);
  }, [animateOn, text, characters]);

  return {
    containerRef,
    displayText,
    handleClick,
    isAnimating,
    isDecrypted,
    resetToPlainText,
    revealedIndices,
    triggerHoverDecrypt,
  };
}
