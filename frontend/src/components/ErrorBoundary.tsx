import { Component, ErrorInfo, ReactNode } from 'react';

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  message: string;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  public constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, message: '' };
  }

  public static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, message: error.message };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    console.error('UI error boundary caught an error', { error, errorInfo });
  }

  public render(): ReactNode {
    if (this.state.hasError) {
      return (
        <div className="flex min-h-[40vh] items-center justify-center px-6 py-12">
          <div className="max-w-lg rounded-2xl border border-rose-300 bg-rose-50 p-8 text-rose-900 shadow-sm">
            <h2 className="text-xl font-semibold">Something went wrong.</h2>
            <p className="mt-3 text-sm opacity-90">{this.state.message || 'Unexpected rendering error.'}</p>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
