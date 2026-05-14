import { useRadio } from "@heroui/radio";
import { cn } from "@heroui/theme";
import { VisuallyHidden } from "@react-aria/visually-hidden";
import React from "react";

interface CustomRadioProps {
  description?: string;
  value?: string;
  children?: React.ReactNode;
}

export const CustomRadio: React.FC<CustomRadioProps> = (props) => {
  const {
    Component,
    children,
    // description,
    getBaseProps,
    getWrapperProps,
    getInputProps,
    getLabelProps,
    getLabelWrapperProps,
    getControlProps,
  } = useRadio({ ...props, value: props.value || "" });

  return (
    <Component
      {...getBaseProps()}
      className={cn(
        "group tap-highlight-transparent inline-flex flex-row-reverse items-center justify-between hover:opacity-70 active:opacity-50",
        "border-default max-w-full cursor-pointer gap-4 rounded-lg border-2 p-4",
        "hover:border-button-primary data-[selected=true]:border-button-primary w-full",
      )}
    >
      <VisuallyHidden>
        <input {...getInputProps()} />
      </VisuallyHidden>
      <span {...getWrapperProps()}>
        <span {...getControlProps()} />
      </span>
      <div {...getLabelWrapperProps()}>
        {children && <span {...getLabelProps()}>{children}</span>}
        {/* {description && (
            <span className="text-small text-foreground opacity-70">
              {description}
            </span>
          )} */}
      </div>
    </Component>
  );
};
