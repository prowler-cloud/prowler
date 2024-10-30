import { UseRadioProps } from "@nextui-org/radio/dist/use-radio";
import { cn, useRadio, VisuallyHidden } from "@nextui-org/react";
import React from "react";

interface CustomRadioProps extends UseRadioProps {
  description?: string;
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
  } = useRadio(props);

  return (
    <Component
      {...getBaseProps()}
      className={cn(
        "group inline-flex flex-row-reverse items-center justify-between tap-highlight-transparent hover:opacity-70 active:opacity-50",
        "max-w-full cursor-pointer gap-4 rounded-lg border-2 border-default p-4",
        "w-full hover:border-action data-[selected=true]:border-action",
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
