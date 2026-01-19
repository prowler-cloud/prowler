import { CustomLink } from "@/components/ui/custom/custom-link";

interface AuthFooterLinkProps {
  text: string;
  linkText: string;
  href: string;
}

export const AuthFooterLink = ({
  text,
  linkText,
  href,
}: AuthFooterLinkProps) => {
  return (
    <p className="text-small text-center">
      {text}&nbsp;
      <CustomLink size="md" href={href} target="_self">
        {linkText}
      </CustomLink>
    </p>
  );
};
