package com.edulearn.payment.service;

import com.edulearn.payment.dto.PaymentDto;
import com.edulearn.payment.entity.Subscription;

import java.util.List;

public interface PaymentService {
    PaymentDto.PaymentResponse      processPayment(Long studentId, PaymentDto.PaymentRequest request);
    List<PaymentDto.PaymentResponse> getPaymentsByStudent(Long studentId);
    java.util.Map<String, Object> createRazorpayOrder(Long courseId, java.math.BigDecimal amount);
    PaymentDto.PaymentResponse verifyRazorpayPayment(Long studentId, java.util.Map<String, String> payload);
    PaymentDto.PaymentResponse      refundPayment(Long paymentId);
    PaymentDto.SubscriptionResponse subscribe(Long studentId, PaymentDto.SubscriptionRequest request);
    PaymentDto.SubscriptionResponse getSubscription(Long studentId);
    PaymentDto.SubscriptionResponse cancelSubscription(Long studentId);
    PaymentDto.SubscriptionResponse renewSubscription(Long studentId);
    boolean                          isSubscriptionActive(Long studentId);
    PaymentDto.RevenueResponse       getPlatformRevenue();
}
