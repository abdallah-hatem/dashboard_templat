"use client";

import Table from "@/components/functional/table";
import useTable from "./useTable";
import { useTranslations } from "next-intl";
import { useDebouncedSearch } from "@/hooks/useDebouncedSearch";
import ButtonComp from "@/components/functional/buttonComp";
import { useRef } from "react";
import { useRouter, useSearchParams } from "next/navigation";

interface TestsClientProps {
  data: any;
  meta: any;
}

export default function TestClient({ data, meta }: TestsClientProps) {
  const t = useTranslations();
  const router = useRouter();
  const searchParams = useSearchParams();
  const { columns, formFields, actions } = useTable();
  const tableCreateRef = useRef<(() => void) | null>(null);

  const { searchValue, handleSearchChange } = useDebouncedSearch(
    "keyword",
    400,
  );

  const onUpdate = async (id: string | number, values: any) => {
    // return await UPDATE_BRANCH({
    //   id: String(id),
    //   data: values,
    // });
  };

  const onAdd = async (values: any) => {
    // return await CREATE_BRANCH({ data: values });
  };

  const onDelete = async (id: string | number) => {
    // return await DELETE_BRANCH({ id: String(id) });
  };

  const filters = [
    {
      filterKey: "branch_id",
      label: "all_branches",
      options: [{ label: "all_branches", value: "" }],
    },
    {
      filterKey: "status",
      label: "status",
      options: [
        { label: "pending", value: "Pending" },
        { label: "incomplete_profile", value: "InComplete Profile" },
        { label: "active", value: "Active" },
        { label: "package_expired", value: "Package Expired" },
        { label: "application_not_paid", value: "Application Not Paid" },
      ],
    },
  ];

  return (
    <>
      <Table
        title={"branch"}
        columns={columns}
        dataSource={data}
        loading={false}
        addButtonText={"add_branch"}
        addButtonSubText={"add_branch_sub_text"}
        searchPlaceholder={"search_placeholder"}
        rowKey="id"
        actions={actions}
        genericFilters={filters}
        pagination={{
          pageSize: meta?.per_page,
          total: meta?.total,
          current: meta?.current_page,
          onChange: (page, pageSize) => {
            // Create new URLSearchParams from current search params to preserve all existing parameters
            const params = new URLSearchParams(searchParams.toString());
            params.set("page", page.toString());

            router.replace(`/test?${params.toString()}`, { scroll: false });
          },
        }}
        emptyStateTitle={"branches_title"}
        emptyStateDescription={"branches_description"}
        emptyStateIcon={<></>}
        searchable
        searchValue={searchValue}
        onSearchChange={handleSearchChange}
        onAdd={onAdd}
        onUpdate={onUpdate}
        onDelete={onDelete}
        formFields={formFields}
        onCreateRef={tableCreateRef}
      />
    </>
  );
}
