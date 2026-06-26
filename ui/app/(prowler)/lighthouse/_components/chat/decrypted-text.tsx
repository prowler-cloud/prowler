"use client";

import { type HTMLMotionProps, motion } from "framer-motion";
import { useEffect, useRef, useState } from "react";

import { cn } from "@/lib/utils";

type RevealDirection = "start" | "end" | "center";
type Direction = "forward" | "reverse";

interface DecryptedTextProps extends HTMLMotionProps<"span"> {
  text: string;
  speed?: number;
  maxIterations?: number;
  sequential?: boolean;
  revealDirection?: RevealDirection;
  useOriginalCharsOnly?: boolean;
  characters?: string;
  className?: string;
  encryptedClassName?: string;
  parentClassName?: string;
  animateOn?: "view" | "hover" | "inViewHover" | "click";
  clickMode?: "once" | "toggle";
}

const DEFAULT_CHARACTERS =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*()_+";

// Pure helpers live at module scope so they are never reactive effect deps —
// this is what lets us drop useCallback (banned here) without lint warnings.
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

// Ported from reactbits DecryptedText, adapted to Prowler conventions:
// framer-motion import, no useMemo/useCallback (React Compiler), pure helpers
// hoisted to module scope, and IntersectionObserver guarded for SSR/test safety.
export function DecryptedText({
  text,
  speed = 50,
  maxIterations = 10,
  sequential = false,
  revealDirection = "start",
  useOriginalCharsOnly = false,
  characters = DEFAULT_CHARACTERS,
  className = "",
  parentClassName = "",
  encryptedClassName = "",
  animateOn = "hover",
  clickMode = "once",
  ...props
}: DecryptedTextProps) {
  const [displayText, setDisplayText] = useState<string>(text);
  const [isAnimating, setIsAnimating] = useState<boolean>(false);
  const [revealedIndices, setRevealedIndices] = useState<Set<number>>(
    new Set(),
  );
  const [hasAnimated, setHasAnimated] = useState<boolean>(false);
  const [isDecrypted, setIsDecrypted] = useState<boolean>(
    animateOn !== "click",
  );
  const [direction, setDirection] = useState<Direction>("forward");

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
    setDirection("forward");
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
    setDirection("reverse");
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
          if (direction === "forward") {
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
          // reverse
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

        // non-sequential
        if (direction === "forward") {
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

        // non-sequential reverse
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
    setDirection("forward");
    setIsAnimating(true);
  };

  const resetToPlainText = () => {
    clearInterval(intervalRef.current ?? undefined);
    setIsAnimating(false);
    setRevealedIndices(new Set());
    setDisplayText(text);
    setIsDecrypted(true);
    setDirection("forward");
  };

  useEffect(() => {
    if (animateOn !== "view" && animateOn !== "inViewHover") return;
    // SSR / jsdom (tests) lack IntersectionObserver: skip the reveal animation,
    // the init effect already renders the plain text so nothing is lost.
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
            setDirection("forward");
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
    setDirection("forward");
  }, [animateOn, text, characters]);

  const animateProps =
    animateOn === "hover" || animateOn === "inViewHover"
      ? { onMouseEnter: triggerHoverDecrypt, onMouseLeave: resetToPlainText }
      : animateOn === "click"
        ? { onClick: handleClick }
        : {};

  return (
    <motion.span
      ref={containerRef}
      className={cn("inline-block whitespace-pre-wrap", parentClassName)}
      {...animateProps}
      {...props}
    >
      <span className="sr-only">{displayText}</span>

      <span aria-hidden="true">
        {displayText.split("").map((char, index) => {
          const isRevealedOrDone =
            revealedIndices.has(index) || (!isAnimating && isDecrypted);

          return (
            <span
              key={index}
              className={isRevealedOrDone ? className : encryptedClassName}
            >
              {char}
            </span>
          );
        })}
      </span>
    </motion.span>
  );
}
