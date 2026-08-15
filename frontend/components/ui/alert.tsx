import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "@/lib/utils"

const alertVariants = cva(
  "relative flex items-start gap-4 overflow-hidden rounded-[16px] border p-[21px] backdrop-blur-md animate-in fade-in slide-in-from-right-full duration-500 text-left text-sm",
  {
    variants: {
      variant: {
        default:
          "border-accent/30 bg-accent/5 text-foreground [&>svg]:text-accent",
        destructive:
          "border-destructive/30 bg-destructive/5 text-foreground [&>svg]:text-destructive",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
)

function Alert({
  className,
  variant = "default",
  children,
  ...props
}: React.ComponentProps<"div"> & VariantProps<typeof alertVariants>) {
  return (
    <div
      data-slot="alert"
      role="alert"
      className={cn(alertVariants({ variant }), className)}
      {...props}
    >
      <div 
        aria-hidden="true" 
        className={cn(
          "absolute left-0 top-0 h-full w-1",
          variant === "destructive" ? "bg-destructive" : "bg-accent"
        )} 
      />
      {children}
    </div>
  )
}

function AlertTitle({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="alert-title"
      className={cn("font-sans text-sm font-medium text-foreground tracking-tight", className)}
      {...props}
    />
  )
}

function AlertDescription({
  className,
  ...props
}: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="alert-description"
      className={cn("font-sans text-sm text-muted-foreground mt-1 leading-[1.5]", className)}
      {...props}
    />
  )
}

function AlertAction({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="alert-action"
      className={cn("absolute top-2.5 right-3", className)}
      {...props}
    />
  )
}

export { Alert, AlertTitle, AlertDescription, AlertAction }
