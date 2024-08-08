"use client";

import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";
import React from "react";

interface Props {
  totalPages: number;
  currentPage: number;
  nextPage?: string;
}

export const Pagination = ({ totalPages, currentPage }: Props) => {
  const pathname = usePathname();
  const searchParams = useSearchParams();
  // const currentPage = searchParams["page"] ?? "1";
  const createPageUrl = (pageNumber: number | string) => {
    const params = new URLSearchParams(searchParams);

    if (pageNumber === "...") return `${pathname}?${params.toString()}`;

    if (+pageNumber <= 0) {
      return `${pathname}`;
    }
    if (+pageNumber > totalPages) {
      return `${pathname}?${params.toString()}`;
    }
    params.set("page", pageNumber.toString());
    return `${pathname}?${params.toString()}`;
  };

  console.log(pathname, searchParams, currentPage);

  return (
    <div className="flex justify-center">
      <nav aria-label="Page navigation example">
        <ul className="flex list-style-none">
          <li className="page-item">
            <Link
              className="page-link relative block py-1.5 px-3 border-0 bg-transparent outline-none transition-all duration-300 rounded text-gray-800 hover:text-gray-800 hover:bg-gray-200 focus:shadow-none"
              href={createPageUrl(currentPage - 1)}
              aria-disabled="true"
            >
              Previous
            </Link>
          </li>

          <li className="page-item">
            <a
              className="page-link relative block py-1.5 px-3 border-0 bg-transparent outline-none transition-all duration-300 rounded text-gray-800 hover:text-gray-800 hover:bg-gray-200 focus:shadow-none"
              href="#"
            >
              1
            </a>
          </li>

          <li className="page-item active">
            <a
              className="page-link relative block py-1.5 px-3 border-0 bg-blue-600 outline-none transition-all duration-300 rounded text-white hover:text-white hover:bg-blue-600 shadow-md focus:shadow-md"
              href="#"
            >
              2 <span className="visually-hidden"></span>
            </a>
          </li>

          <li className="page-item">
            <a
              className="page-link relative block py-1.5 px-3 border-0 bg-transparent outline-none transition-all duration-300 rounded text-gray-800 hover:text-gray-800 hover:bg-gray-200 focus:shadow-none"
              href="#"
            >
              3
            </a>
          </li>
          <li className="page-item">
            <a
              className="page-link relative block py-1.5 px-3 border-0 bg-transparent outline-none transition-all duration-300 rounded text-gray-800 hover:text-gray-800 hover:bg-gray-200 focus:shadow-none"
              href="#"
            >
              ...
            </a>
          </li>

          <li className="page-item">
            <Link
              className="page-link relative block py-1.5 px-3 border-0 bg-transparent outline-none transition-all duration-300 rounded text-gray-800 hover:text-gray-800 hover:bg-gray-200 focus:shadow-none"
              href={"#"}
            >
              Next
            </Link>
          </li>
        </ul>
      </nav>
    </div>
  );
};
