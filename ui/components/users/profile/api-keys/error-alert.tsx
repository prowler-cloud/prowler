interface ErrorAlertProps {
  error: string | null;
}

export const ErrorAlert = ({ error }: ErrorAlertProps) => {
  if (!error) return null;

  return (
    <div className="bg-danger-50 text-danger-600 rounded-lg p-3 text-sm">
      {error}
    </div>
  );
};
