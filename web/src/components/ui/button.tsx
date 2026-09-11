import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import * as React from "react";

import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center whitespace-nowrap rounded-[var(--radius-control)] text-[13px] font-medium transition-colors duration-150 gap-2 [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-black focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--canvas)] disabled:pointer-events-none disabled:opacity-50",
  {
    variants: {
      variant: {
        primary:
          "border-2 border-[var(--outline)] bg-[var(--main)] text-black hover:bg-[var(--primary-hover)]",
        // The one loud button, and only inside the ticket: white tile, black frame, hard shadow.
        raised:
          "border-2 border-[var(--outline)] bg-white font-semibold text-black shadow-[3px_3px_0_0_#000] transition-[transform,box-shadow,background-color] hover:translate-x-[1px] hover:translate-y-[1px] hover:shadow-[2px_2px_0_0_#000] active:translate-x-[3px] active:translate-y-[3px] active:shadow-none motion-reduce:transform-none motion-reduce:hover:shadow-[3px_3px_0_0_#000]",
        secondary:
          "border border-[var(--outline)] bg-white text-[var(--ink)] hover:bg-[var(--hover)]",
        // Text-only action that sits on the ticket fill.
        quiet: "bg-transparent px-2 text-current hover:underline",
        ghost:
          "text-[var(--subtext)] hover:bg-[var(--hover)] hover:text-[var(--ink)]",
        destructive:
          "border border-[var(--outline)] bg-white text-[var(--danger)] hover:bg-[var(--hover)]",
        // Legacy aliases kept so existing call sites compile; all render flat.
        noShadow:
          "border-2 border-[var(--outline)] bg-[var(--main)] text-black hover:bg-[var(--primary-hover)]",
        neutral:
          "border border-[var(--outline)] bg-white text-[var(--ink)] hover:bg-[var(--hover)]",
        reverse:
          "border-2 border-[var(--outline)] bg-[var(--main)] text-black hover:bg-[var(--primary-hover)]",
      },
      size: {
        default: "h-8 px-3.5",
        sm: "h-8 px-3 text-[12px]",
        lg: "h-10 px-6",
        icon: "size-9",
      },
    },
    defaultVariants: {
      variant: "primary",
      size: "default",
    },
  },
);

type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> &
  VariantProps<typeof buttonVariants> & {
    asChild?: boolean;
  };

function Button({
  className,
  variant,
    size,
  asChild = false,
  ...props
}: ButtonProps) {
  const Comp = asChild ? Slot : "button";

  return (
    <Comp className={cn(buttonVariants({ variant, size }), className)} {...props} />
  );
}

export { Button, buttonVariants };
