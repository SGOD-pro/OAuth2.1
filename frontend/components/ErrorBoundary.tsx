import React, { Component, type ErrorInfo, type ReactNode } from 'react';
import { Button } from './ui/button';

interface Props {
  children: ReactNode;
  fallbackTitle?: string;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught error in UI component:', error, errorInfo);
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null });
    window.location.reload();
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-[400px] flex items-center justify-center p-6">
          <div className="max-w-md w-full rounded-2xl border border-destructive/30 bg-destructive/5 p-6 text-center space-y-4 shadow-lg">
            <div className="w-12 h-12 rounded-full bg-destructive/10 text-destructive flex items-center justify-center mx-auto text-xl font-bold">
              !
            </div>
            <h2 className="text-lg font-semibold text-foreground">
              {this.props.fallbackTitle || 'Something went wrong'}
            </h2>
            <p className="text-xs text-muted-foreground font-mono break-all">
              {this.state.error?.message || 'An unexpected rendering error occurred.'}
            </p>
            <div className="pt-2 flex justify-center gap-3">
              <Button size="sm" variant="outline" onClick={() => window.history.back()}>
                Go Back
              </Button>
              <Button size="sm" onClick={this.handleReset}>
                Reload Page
              </Button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
