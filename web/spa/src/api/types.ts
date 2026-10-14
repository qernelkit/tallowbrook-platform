export type ShipmentStatus =
  | 'booked'
  | 'awaiting_collection'
  | 'collected'
  | 'in_transit'
  | 'out_for_delivery'
  | 'delivered'
  | 'exception'
  | 'returned'
  | 'cancelled';

export interface Address {
  name: string;
  street: string;
  city: string;
  postcode: string;
  country: string;
  phone?: string;
}

export interface Parcel {
  weightGrams: number;
  lengthCm: number;
  widthCm: number;
  heightCm: number;
}

export interface BookingDraft {
  service: 'standard' | 'express' | 'economy';
  sender: Address;
  consignee: Address;
  parcels: Parcel[];
  collectionDate?: string;
  deliveryNote?: string;
}

export interface ShipmentSummary {
  _id: string;
  publicId: string;
  status: ShipmentStatus;
  service: string;
  consignee: Address;
  createdAt: string;
}

export interface TrackingEvent {
  status: ShipmentStatus;
  at: string;
  depot: string | null;
}

export interface Quote {
  carrier: string;
  service: string;
  amountMinor: number;
  currency: string;
  estimatedDelivery: string;
}

export interface Account {
  id: string;
  email: string;
  name: string;
  role: 'shipper' | 'approver' | 'admin';
}

export interface ApproverKeyOptions {
  challenge: string;
  rpId: string;
}

export interface CustomsReceipt {
  receiptId: string;
  shipmentId: string;
  entryNumber: string;
  issuedAt: string;
  procedure: string;
  signature: string;
}

export interface TrainingCourse {
  title: string;
  provider: string;
  certificate: { number: string; expiresOn: string };
}

export interface TrainingCredential {
  '@context': string[];
  type: string[];
  issuer: string;
  issuanceDate: string;
  expirationDate?: string;
  credentialSubject: { id: string; course: TrainingCourse };
  proof: {
    type: string;
    created: string;
    verificationMethod: string;
    proofPurpose: string;
    proofValue: string;
  };
}

export interface Claim {
  id: string;
  shipmentId: string;
  reason: 'damaged' | 'missing_items' | 'not_delivered' | 'late';
  status: 'open' | 'reviewing' | 'paid' | 'rejected';
  amountMinor: number;
}
