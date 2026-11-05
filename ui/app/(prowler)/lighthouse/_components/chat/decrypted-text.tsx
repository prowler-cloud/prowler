"use client";

import { type HTMLMotionProps, motion } from "framer-motion";

import { cn } from "@/lib/utils";

import {
  type DecryptedTextAnimateOn,
  type DecryptedTextClickMode,
  DEFAULT_CHARACTERS,
  type RevealDirection,
  useDecryptedTextController,
} from "./decrypted-text-hooks";

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
  animateOn?: DecryptedTextAnimateOn;
  clickMode?: DecryptedTextClickMode;
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
  const {
    containerRef,
    displayText,
    handleClick,
    isAnimating,
    isDecrypted,
    resetToPlainText,
    revealedIndices,
    triggerHoverDecrypt,
  } = useDecryptedTextController({
    text,
    speed,
    maxIterations,
    sequential,
    revealDirection,
    useOriginalCharsOnly,
    characters,
    animateOn,
    clickMode,
  });

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
      <span className="sr-only">{text}</span>

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
