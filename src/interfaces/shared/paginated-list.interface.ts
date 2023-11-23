export interface PaginatedList<T = unknown> {
  self: string;
  items: T[];
  total: number;
  pageSize: number;
  links: {
    first: string;
    prev: string;
    next: string;
    last: string;
  };
}

export interface PaginatedListCassandra<T> {
  self: string;
  items: T[];
  total?: number;
  pageSize: number;
  links: {
    next?: string;
  };
}
