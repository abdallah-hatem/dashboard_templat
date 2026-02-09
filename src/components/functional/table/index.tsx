import React, { useEffect } from "react";
import {
  Table as AntTable,
  Spin,
  Empty,
  PaginationProps,
  FormInstance,
} from "antd";
import type { ColumnsType, TableProps } from "antd/es/table";
import useModal from "@/hooks/useModal";
import { formFieldsType } from "@/components/form/formComp";
import TopBar from "./topBar";
import TableActions from "./tableActions";
import CustomPagination from "./CustomPagination";
import EmptyStateComp from "@/components/shared/emptyStateComp";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { GenericFilterProps } from "./GenericFilter";
import { useTableSort } from "./hooks/useTableSort";
import { useTableSearch } from "./hooks/useTableSearch";
import { useTableActions } from "./hooks/useTableActions";
import { useTableScroll } from "./hooks/useTableScroll";
import {
  buildDefaultActions,
  enhanceColumnsWithSort,
} from "./utils/tableUtils";
import useIsArabic from "@/hooks/useIsArabic";

export interface IAction {
  label: string;
  onClick: (record: any) => void;
  disabled?: boolean;
  danger?: boolean;
  hide?: (record: any) => boolean;
  icon?: React.ReactNode;
  customRender?: (record: any) => React.ReactNode;
}

export interface ITableProps<T = any> {
  columns: ColumnsType<T>;
  dataSource?: T[];
  loading?: boolean;
  actions?: IAction[];
  searchable?: boolean;
  title?: string;
  emptyText?: string;
  serverPagination?: boolean;
  pagination?: PaginationProps | false;
  total?: number;
  currentPage?: number;
  pageSize?: number;
  onPageChange?: (page: number, pageSize: number) => void;
  onChange?: TableProps<T>["onChange"];
  rowKey?: string;
  scroll?: { x?: number | string; y?: number | string };
  addButton?: boolean;
  formFields?: formFieldsType;
  formFieldsUpdate?: formFieldsType;
  additionalUpdateValues?: Record<string, any>;
  onAdd?: (values: any) => Promise<any>;
  onUpdate?: (id: string | number, values: any) => Promise<any>;
  onDelete?: (id: string | number) => Promise<any>;
  addButtonText?: string;
  addButtonSubText?: string;
  hideDefaultUpdate?: boolean;
  hideDefaultDelete?: boolean;
  fieldMapping?: Record<string, string>;
  transformForForm?: (values: any) => any;
  virtualScroll?: boolean;
  createButtonHref?: string;
  searchValue?: string;
  onSearchChange?: (value: string) => void;
  formRefAdd?: FormInstance;
  formRefEdit?: FormInstance;
  sortable?: boolean;
  onSort?: (sortBy: string, sortOrder: "asc" | "desc") => void;
  currentSort?: {
    sort_by?: string;
    sort?: "asc" | "desc";
  };
  hideSearch?: boolean;
  onCreateRef?: React.MutableRefObject<(() => void) | null>;
  genericFilters?: GenericFilterProps[];
  rowSelection?: TableProps<T>["rowSelection"];
  onRow?: (record: T, index?: number) => React.HTMLAttributes<any>;
  emptyStateTitle?: string;
  emptyStateDescription?: string;
  emptyStateIcon?: React.ReactNode;
  searchPlaceholder?: string;
  searchStyleTw?: string;
}

const Table = <T extends object>({
  columns = [],
  dataSource,
  loading = false,
  actions = [],
  searchable = false,
  title = "",
  emptyText = "No data found",
  serverPagination = false,
  pagination,
  total = 0,
  currentPage = 1,
  pageSize = 10,
  onPageChange,
  onChange,
  rowKey = "id",
  scroll = { x: 1000 },
  addButton = false,
  formFields = [],
  formFieldsUpdate,
  additionalUpdateValues = {},
  onAdd,
  onUpdate,
  onDelete,
  addButtonText = "Add New",
  addButtonSubText = "",
  hideDefaultUpdate = false,
  hideDefaultDelete = false,
  fieldMapping = {},
  transformForForm,
  virtualScroll = false,
  createButtonHref,
  searchValue = "",
  onSearchChange,
  formRefAdd,
  formRefEdit,
  sortable = false,
  onSort,
  currentSort = {},
  hideSearch = false,
  onCreateRef,
  genericFilters,
  rowSelection,
  onRow,
  emptyStateTitle,
  emptyStateDescription,
  emptyStateIcon,
  searchPlaceholder,
  searchStyleTw,
}: ITableProps<T>) => {
  const router = useRouter();
  const t = useTranslations();
  const isRTL = useIsArabic();
  const updateFields = formFieldsUpdate || [];
  const defaultFields = formFields || [];

  // Modal setup
  const { renderModal, showModal, hideModal } = useModal({
    modalProps: {
      footer: null,
      width: 500,
      style: { top: "5%" },
      styles: {
        wrapper: {
          borderRadius: "30px",
        },
        body: {
          maxHeight: "75vh",
          overflow: "auto",
          marginTop: "0px",
        },
      },
    },
  });

  // Use custom hooks
  const { sortState, handleSort } = useTableSort({
    currentSort,
    sortable,
    onSort,
  });

  const { filteredData, getCurrentData } = useTableSearch({
    dataSource,
    searchable,
    serverPagination,
  });

  const { handleAdd, handleUpdate } = useTableActions({
    formFields,
    formFieldsUpdate,
    additionalUpdateValues,
    onAdd,
    onUpdate,
    onDelete,
    addButtonText,
    addButtonSubText,
    fieldMapping,
    transformForForm,
    rowKey,
    title,
    formRefAdd,
    formRefEdit,
    showModal,
    hideModal,
  });

  const { tableScroll } = useTableScroll({
    dataSource,
    filteredData,
    searchable,
    serverPagination,
    isRTL,
    scroll,
  });

  // Get the current data to render
  const currentData = getCurrentData();

  // Build actions with defaults
  const allActions = buildDefaultActions({
    actions,
    hideDefaultDelete,
    hideDefaultUpdate,
    onDelete,
    onUpdate,
    defaultFields,
    updateFields,
    handleUpdate,
    rowKey,
    t,
  });

  // Enhance columns with sorting functionality
  const enhancedColumns = enhanceColumnsWithSort({
    columns,
    sortable,
    sortState,
    handleSort,
    isRTL,
  });

  // Add actions column if actions are provided
  const tableColumns = [...enhancedColumns];
  if (allActions.length > 0) {
    tableColumns.push({
      title: "",
      key: "actions",
      fixed: isRTL ? "left" : "right",
      width: 100,
      render: (_, record) => (
        <div className={`${isRTL ? "ml-auto" : "mr-auto"} w-fit `}>
          <TableActions actions={allActions} record={record} />
        </div>
      ),
    });
  }

  const handleCreate = () => {
    if (createButtonHref) {
      router.push(createButtonHref);
    } else {
      handleAdd();
    }
  };

  // Expose handleCreate to parent component via ref
  useEffect(() => {
    if (onCreateRef) {
      onCreateRef.current = handleCreate;
    }
  }, [onCreateRef, createButtonHref, formFields, onAdd]);

  return (
    <div className="w-full">
      {/* Header with search and generic filters */}
      {(title || searchable || addButton || genericFilters) && (
        <TopBar
          searchStyleTw={searchStyleTw}
          searchPlaceholder={searchPlaceholder}
          searchValue={searchValue}
          onSearchChange={onSearchChange}
          hideSearch={hideSearch}
          genericFilters={genericFilters}
        />
      )}

      {/* Table or Empty State */}
      <Spin spinning={loading}>
        <div className="custom-shadow rounded-[5px] bg-white p-[20px]">
          {dataSource && dataSource.length > 0 ? (
            <AntTable
              columns={isRTL ? tableColumns.reverse() : tableColumns}
              dataSource={currentData}
              rowKey={rowKey}
              pagination={false}
              onChange={onChange}
              locale={{
                emptyText: <Empty description={emptyText} />,
              }}
              scroll={tableScroll}
              className={`[&_.ant-table-thead_.ant-table-cell]:!bg-gray-100 [&_.ant-table-thead_.ant-table-cell]:!font-semibold [&_.ant-table-thead_.ant-table-cell]:!text-gray-700 [&_.ant-table-header]:!bg-gray-100 [&_.ant-table-header]:!font-semibold [&_.ant-table-header]:!rounded-[0px]   ${
                isRTL
                  ? "[&_.ant-table-cell]:!text-right [&_.ant-table-container]:!overflow-hidden"
                  : "[&_.ant-table-cell]:!text-left"
              }`}
              virtual={virtualScroll}
              rowSelection={rowSelection}
              onRow={onRow}
            />
          ) : (
            <EmptyStateComp
              title={emptyStateTitle}
              description={emptyStateDescription}
              icon={emptyStateIcon}
            />
          )}
        </div>
      </Spin>

      {/* Custom Pagination Bar */}
      {dataSource && dataSource?.length > 0 && (
        <CustomPagination
          showCount={true}
          current={
            serverPagination
              ? currentPage
              : (pagination && pagination?.current) || 1
          }
          pageSize={
            serverPagination
              ? pageSize
              : (pagination && pagination?.pageSize) || 10
          }
          total={
            serverPagination ? total : (pagination && pagination?.total) || 0
          }
          onChange={(page) => {
            if (serverPagination && onPageChange) {
              onPageChange(
                page,
                serverPagination
                  ? pageSize
                  : (pagination && pagination?.pageSize) || 10,
              );
            } else if (pagination && pagination.onChange) {
              pagination.onChange(
                page,
                (pagination && pagination?.pageSize) || 10,
              );
            }
          }}
        />
      )}

      {renderModal()}
    </div>
  );
};

export default Table;
