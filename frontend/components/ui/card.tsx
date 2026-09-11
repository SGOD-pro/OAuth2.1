import * as React from "react"
import { cn } from "@/lib/utils"

function Card({
  className,
  size = "default",
  accent = "none",
  children,
  ...props
}: React.ComponentProps<"div"> & { 
  size?: "default" | "sm"; 
  accent?: "motorsport" | "none";
}) {
  return (
    <div
      data-slot="card"
      data-size={size}
      className={cn(
        "relative overflow-hidden rounded-[12px] border border-border bg-card shadow-xs text-card-foreground",
        className
      )}
      {...props}
    >
      {/* Optional BMW M-Series Motorsport Accent Top Segment */}
      {accent === "motorsport" && (
        <div aria-hidden="true" className="absolute top-0 left-0 right-0 h-[2.5px] flex pointer-events-none z-20">
          <div className="w-1/3 h-full bg-[#0066B1]" />
          <div className="w-1/3 h-full bg-[#1C69D4]" />
          <div className="w-1/3 h-full bg-[#E22718]" />
        </div>
      )}

      <div className="relative z-10 w-full">
        {children}
      </div>
    </div>
  )
}

function CardHeader({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="card-header"
      className={cn(
        "flex flex-col space-y-1.5 p-5 sm:p-6 pb-0",
        className
      )}
      {...props}
    />
  )
}

function CardTitle({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="card-title"
      className={cn(
        "font-heading text-lg font-semibold leading-tight tracking-tight text-foreground",
        className
      )}
      {...props}
    />
  )
}

function CardDescription({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="card-description"
      className={cn("text-xs font-sans text-muted-foreground", className)}
      {...props}
    />
  )
}

function CardAction({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="card-action"
      className={cn(
        "col-start-2 row-span-2 row-start-1 self-start justify-self-end",
        className
      )}
      {...props}
    />
  )
}

function CardContent({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="card-content"
      className={cn("p-5 sm:p-6", className)}
      {...props}
    />
  )
}

function CardFooter({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="card-footer"
      className={cn(
        "flex items-center p-5 sm:p-6 pt-0",
        className
      )}
      {...props}
    />
  )
}

export {
  Card,
  CardHeader,
  CardFooter,
  CardTitle,
  CardAction,
  CardDescription,
  CardContent,
}
