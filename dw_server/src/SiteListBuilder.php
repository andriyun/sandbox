<?php

/**
 * @file
 * Contains \Drupal\dw_server\SiteListBuilder.
 */

namespace Drupal\dw_server;

use Drupal\Component\Utility\SafeMarkup;
use Drupal\Core\Config\Entity\ConfigEntityListBuilder;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Url;

/**
 * Defines a class to build a listing of site entities.
 *
 * @see \Drupal\dw_server\Entity\Site
 */
class SiteListBuilder extends ConfigEntityListBuilder {

  /**
   * {@inheritdoc}
   */
  public function buildHeader() {
    $header['label'] = $this->t('Site label');
    $header['url'] = [
      'data' => $this->t('Site url'),
      'class' => [RESPONSIVE_PRIORITY_MEDIUM],
    ];
    return $header + parent::buildHeader();
  }

  /**
   * {@inheritdoc}
   */
  public function buildRow(EntityInterface $entity) {
    $row['label'] = ['data' => [
      '#type' => 'link',
      '#title' => $entity->label(),
      '#url' => $entity->urlInfo('canonical'),
    ]];
    $row['url'] = SafeMarkup::checkPlain($entity->get('url'));
    return $row + parent::buildRow($entity);
  }

  /**
   * {@inheritdoc}
   */
  public function getDefaultOperations(EntityInterface $entity) {
    $operations = parent::getDefaultOperations($entity);
    $operations['overview'] = [
      'title' => $this->t('Overview'),
      'weight' => -100,
      'url' => $entity->urlInfo('canonical'),
    ];
    $operations['add'] = [
      'title' => $this->t('Add report (testing)'),
      'weight' => -50,
      'url' => Url::fromRoute('entity.watchtower_report.add_form', [
        'watchtower_site' =>$entity->id(),
      ]),
    ];
    return $operations;
  }

}