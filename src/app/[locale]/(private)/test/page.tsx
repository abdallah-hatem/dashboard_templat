import TestClient from "./testClient";
// import { GET_BRANCHES, GET_BRANCHES_STATS } from "@/apis";

interface TestProps {
  searchParams: Promise<{ [key: string]: string | string[] | undefined }>;
}

// Demo data based on useTable columns
const demoData = [
  {
    id: 1,
    name: "Downtown Branch",
    listing_count: 45,
    agents_count: 12,
    is_master: true,
    phone: "1234567890",
    address: "123 Main Street, Downtown",
  },
  {
    id: 2,
    name: "Westside Office",
    listing_count: 28,
    agents_count: 8,
    is_master: false,
    phone: "9876543210",
    address: "456 West Avenue, Westside",
  },
  {
    id: 3,
    name: "Eastside Branch",
    listing_count: 63,
    agents_count: 15,
    is_master: false,
    phone: "5551234567",
    address: "789 East Boulevard, Eastside",
  },
  {
    id: 4,
    name: "Northside Center",
    listing_count: 31,
    agents_count: 10,
    is_master: false,
    phone: "5559876543",
    address: "321 North Road, Northside",
  },
  {
    id: 5,
    name: "Southside Office",
    listing_count: 52,
    agents_count: 13,
    is_master: false,
    phone: "5552468013",
    address: "654 South Street, Southside",
  },
  {
    id: 6,
    name: "Central Hub",
    listing_count: 89,
    agents_count: 20,
    is_master: false,
    phone: "5558642097",
    address: "987 Central Plaza, City Center",
  },
  {
    id: 7,
    name: "Harbor Branch",
    listing_count: 19,
    agents_count: 6,
    is_master: false,
    phone: "5553691472",
    address: "147 Harbor View, Harbor District",
  },
  {
    id: 8,
    name: "Airport Office",
    listing_count: 41,
    agents_count: 11,
    is_master: false,
    phone: "5557539514",
    address: "258 Airport Road, Airport Area",
  },
  {
    id: 9,
    name: "University Branch",
    listing_count: 36,
    agents_count: 9,
    is_master: false,
    phone: "5551597536",
    address: "369 Campus Drive, University District",
  },
  {
    id: 10,
    name: "Suburban Branch",
    listing_count: 24,
    agents_count: 7,
    is_master: false,
    phone: "5554862739",
    address: "753 Suburban Lane, Suburbs",
  }, {
    id: 11,
    name: "Suburban Branch",
    listing_count: 24,
    agents_count: 7,
    is_master: false,
    phone: "5554862739",
    address: "753 Suburban Lane, Suburbs",
  },
];

export default async function Test({ searchParams }: TestProps) {
  // const { data, current_page, per_page, total } = await GET_BRANCHES({
  //   searchParams: await searchParams,
  // });

  // const { data: stats } = await GET_BRANCHES_STATS();

  return (
    <TestClient
      data={demoData}
      meta={{ current_page: 1, per_page: 10, total: demoData.length }}
    />
  );
}
